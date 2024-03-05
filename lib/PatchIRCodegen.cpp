/*
 * Copyright (c) 2024-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "anvill/Declarations.h"

#include <anvill/Optimize.h>
#include <anvill/Providers.h>
#include <anvill/Specification.h>
#include <irene3/PatchIR/PatchIRAttrs.h>
#include <irene3/PatchIR/PatchIRDialect.h>
#include <irene3/PatchIR/PatchIROps.h>
#include <irene3/PatchIR/PatchIRTypes.h>
#include <irene3/PatchIRCodegen.h>
#include <irene3/Transforms/RemoveProgramCounterAndMemory.h>
#include <irene3/Util.h>
#include <llvm/Analysis/CGSCCPassManager.h>
#include <llvm/Analysis/LoopAnalysisManager.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Passes/OptimizationLevel.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <mlir/Dialect/LLVMIR/LLVMDialect.h>
#include <mlir/IR/Attributes.h>
#include <mlir/IR/BuiltinAttributes.h>
#include <mlir/IR/BuiltinOps.h>
#include <mlir/IR/MLIRContext.h>
#include <mlir/IR/OwningOpRef.h>
#include <mlir/Support/LLVM.h>
#include <mlir/Target/LLVMIR/Import.h>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

namespace
{
    // This function removes all of the lifetime intrinsics from an LLVM module.
    //
    // This is needed because such annotations are not supported by the LLVMIR dialect and cause
    // issues during conversion.
    static void removeIntrinsics(llvm::Module &mod) {
        std::vector< llvm::Instruction * > to_remove;
        for (auto &func : mod.functions()) {
            for (auto &inst : llvm::instructions(func)) {
                auto intrinsic = llvm::dyn_cast< llvm::IntrinsicInst >(&inst);
                if (!intrinsic) {
                    continue;
                }

                if (!llvm::isLifetimeIntrinsic(intrinsic->getIntrinsicID())
                    && intrinsic->getIntrinsicID()
                           != llvm::Intrinsic::experimental_noalias_scope_decl) {
                    continue;
                }
                to_remove.push_back(intrinsic);
            }
        }
        for (auto inst : to_remove) {
            inst->eraseFromParent();
        }
    }

} // namespace

namespace irene3
{
    PatchIRCodegen::PatchIRCodegen(
        mlir::MLIRContext &mlir_context,
        std::istream &spec_stream,
        std::unordered_set< uint64_t > &&target_funcs)
        : target_funcs(std::move(target_funcs))
        , mlir_context(mlir_context)
        , spec(DecodeSpec(spec_stream))
        , module(LiftSpec())
        , block_contexts(spec.GetBlockContexts())
        , llvm_to_mlir_type(mlir_context) {
        auto tmp_mod = llvm::CloneModule(*module);
        removeIntrinsics(*tmp_mod);
        mlir_module = mlir::translateLLVMIRToModule(std::move(tmp_mod), &mlir_context);
        if (!mlir_module) {
            throw std::runtime_error("failed to represent LLVM in mlir");
        }
        this->ptr_type = mlir::LLVM::LLVMPointerType::get(&mlir_context);
        mlir_module->getOperation()->setAttr(
            mlir::LLVM::LLVMDialect::getDataLayoutAttrName(),
            StringAttr(spec.Arch()->DataLayout().getStringRepresentation()));
        mlir_module->getOperation()->setAttr(
            mlir::LLVM::LLVMDialect::getTargetTripleAttrName(),
            StringAttr(spec.Arch()->Triple().str()));

        for (const auto &[nm, gv] : this->gvars) {
            mlir::OpBuilder mlir_builder(&this->mlir_context);
            auto unk_loc = mlir_builder.getUnknownLoc();

            mlir_builder.setInsertionPointToEnd(mlir_module->getBody());
            mlir_builder.create< irene3::patchir::Global >(
                unk_loc, mlir::StringAttr::get(&mlir_context, nm), mlir::StringAttr(),
                irene3::patchir::MemoryAttr::get(&mlir_context, gv.address, 0, false, gv.size),
                this->translateType(gv.ty));
        }
        auto addr_ty = mlir::IntegerType::get(
            &mlir_context, spec.Arch()->address_size, mlir::IntegerType::Unsigned);
        auto img_base = this->spec.ImageBase();
        mlir_module->getOperation()->setAttr(
            irene3::patchir::PatchIRDialect::getImageBaseAttrName(),
            mlir::IntegerAttr::get(addr_ty, img_base));

        spec.ForEachFunction([this](auto fdecl) {
            mlir::OpBuilder mlir_builder(&this->mlir_context);
            auto unk_loc = mlir_builder.getUnknownLoc();

            auto flat = irene3::BinaryAddrToFlat(fdecl->binary_addr);

            mlir_builder.setInsertionPointToEnd(mlir_module->getBody());
            auto i64 = mlir::IntegerType::get(&this->mlir_context, 64, mlir::IntegerType::Signed);
            auto u64 = mlir::IntegerType::get(&this->mlir_context, 64, mlir::IntegerType::Unsigned);
            auto funcop = mlir_builder.create< irene3::patchir::FunctionOp >(
                unk_loc, mlir::IntegerAttr::get(u64, flat.addr),
                mlir::IntegerAttr::get(i64, flat.disp),
                mlir::BoolAttr::get(&this->mlir_context, flat.is_external),
                StringAttr(symbol_map[fdecl->address]));
            auto &func_body = funcop.getBody().emplaceBlock();
            mlir_builder.setInsertionPointToEnd(&func_body);

            std::unordered_map< anvill::Uid, std::string > repr_funcs;
            for (llvm::Function &f : module->functions()) {
                auto addr = anvill::GetBasicBlockUid(&f);
                if (addr) {
                    repr_funcs.insert({ *addr, f.getName().str() });
                }
            }

            for (auto &[uid, block] : fdecl->cfg) {
                const anvill::BasicBlockContext &block_ctx
                    = block_contexts.GetBasicBlockContextForUid(uid).value();

                CreateBlockFunc(uid, block, block_ctx, func_body, repr_funcs);
            }

            return true;
        });
        CHECK(mlir_module->verify().succeeded());
    }

    llvm::LLVMContext &PatchIRCodegen::GetLLVMContext() { return llvm_context; }

    anvill::Specification &PatchIRCodegen::GetSpecification() { return spec; }

    mlir::OwningOpRef< mlir::ModuleOp > PatchIRCodegen::GetMLIRModule() {
        return std::move(mlir_module);
    }

    void PatchIRCodegen::NameEntity(llvm::Constant *v, const anvill::EntityLifter &lifter) {
        if (auto addr = lifter.AddressOfEntity(v)) {
            if (auto el = symbol_map.find(*addr); el != symbol_map.end()) {
                v->setName(el->second);
            }
        }
    }

    std::unique_ptr< llvm::Module > PatchIRCodegen::LiftSpec() {
        auto llvm_module = std::make_unique< llvm::Module >("lifted_code", llvm_context);

        anvill::SpecificationTypeProvider spec_tp{ spec };
        anvill::SpecificationControlFlowProvider spec_cfp{ spec };
        anvill::SpecificationMemoryProvider spec_mp{ spec };

        anvill::LifterOptions options(spec.Arch().get(), *llvm_module, spec_tp, spec_cfp, spec_mp);
        options.should_inline_basic_blocks = false;
        options.stack_frame_recovery_options.stack_frame_struct_init_procedure
            = anvill::StackFrameStructureInitializationProcedure::kUndef;
        options.state_struct_init_procedure
            = anvill::StateStructureInitializationProcedure::kGlobalRegisterVariablesAndZeroes;
        options.should_remove_anvill_pc = true;
        options.pc_metadata_name        = "pc";
        anvill::EntityLifter lifter(options);

        spec.ForEachSymbol([this](uint64_t addr, const std::string &name) {
            symbol_map.emplace(addr, name);
            return true;
        });

        spec.ForEachFunction([this, &lifter](auto decl) {
            llvm::Function *func = nullptr;
            if (target_funcs.empty() || target_funcs.find(decl->address) != target_funcs.end()) {
                func = lifter.LiftEntity(*decl);
            }
            // fallback to declaration if we could not lift the entity
            if (!func) {
                func = lifter.DeclareEntity(*decl);
            }

            NameEntity(func, lifter);
            return true;
        });

        spec.ForEachVariable([this, &lifter](auto decl) {
            llvm::Constant *cv = lifter.LiftEntity(*decl);

            NameEntity(cv, lifter);
            return true;
        });

        anvill::OptimizeModule(lifter, *llvm_module, spec.GetBlockContexts(), spec);

        auto cont = spec.GetBlockContexts();
        irene3::RemoveProgramCounterAndMemory pass(cont);
        llvm::PassBuilder pb;

        llvm::ModulePassManager mpm;
        llvm::ModuleAnalysisManager mam;
        llvm::LoopAnalysisManager lam;
        llvm::CGSCCAnalysisManager cam;
        //  llvm::InlineParams params;
        llvm::FunctionAnalysisManager fam;
        pb.registerFunctionAnalyses(fam);
        pb.registerCGSCCAnalyses(cam);
        pb.registerLoopAnalyses(lam);
        pb.registerModuleAnalyses(mam);
        pb.crossRegisterProxies(lam, fam, cam, mam);

        pass.run(*llvm_module, mam);
        auto pipeline = pb.buildModuleOptimizationPipeline(
            llvm::OptimizationLevel::O3, llvm::ThinOrFullLTOPhase::None);

        pipeline.run(*llvm_module, mam);

        // Manually clear the analyses to prevent ASAN failures in the destructors.
        mam.clear();
        fam.clear();
        cam.clear();
        lam.clear();

        removeIntrinsics(*llvm_module);

        std::unordered_set< std::string > symbols_to_lift = spec.GetRequiredGlobals();
        spec.ForEachSymbol([&symbols_to_lift](uint64_t addr, const std::string &name) -> bool {
            symbols_to_lift.insert(name);
            return true;
        });
        for (auto &f : llvm_module->functions()) {
            auto uid = anvill::GetBasicBlockUid(&f);
            if (uid) {
                for (auto var :
                     irene3::UsedGlobalValue< llvm::GlobalVariable >(&f, symbols_to_lift)) {
                    auto pc_metadata = lifter.AddressOfEntity(var);
                    if (!pc_metadata) {
                        continue;
                    }
                    auto v = spec.VariableAt(*pc_metadata);
                    if (v) {
                        size_t sz = v->type->getScalarSizeInBits();
                        gvars.insert({
                            var->getName().str(),
                            {var->getName().str(), *pc_metadata, sz, v->binary_addr,
                                               var->getValueType()}
                        });
                    }
                }
            }
        }

        return llvm_module;
    }

    anvill::Specification PatchIRCodegen::DecodeSpec(std::istream &spec_stream) {
        auto maybe_spec = anvill::Specification::DecodeFromPB(this->llvm_context, spec_stream);
        CHECK(maybe_spec.Succeeded()) << maybe_spec.TakeError();
        return maybe_spec.TakeValue();
    }

    mlir::StringAttr PatchIRCodegen::StringAttr(const std::string &str) {
        return mlir::StringAttr::get(&mlir_context, str);
    }

    mlir::FlatSymbolRefAttr PatchIRCodegen::SymbolRefAttr(const std::string &str) {
        return mlir::SymbolRefAttr::get(&mlir_context, str);
    }

    mlir::Attribute PatchIRCodegen::CreateLowLoc(const anvill::LowLoc &loc) {
        if (loc.reg) {
            return irene3::patchir::RegisterAttr::get(
                &mlir_context, StringAttr(loc.reg->name), loc.Size() * 8);
        } else if (loc.mem_reg) {
            return irene3::patchir::MemoryIndirectAttr::get(
                &mlir_context, StringAttr(loc.mem_reg->name), loc.mem_offset, loc.Size() * 8);
        } else {
            return irene3::patchir::MemoryAttr::get(
                &mlir_context, loc.mem_offset, 0, false, loc.Size() * 8);
        }
    }

    void PatchIRCodegen::translateTypes(
        llvm::ArrayRef< llvm::Type * > types, llvm::SmallVectorImpl< mlir::Type > &result) {
        result.reserve(result.size() + types.size());
        for (llvm::Type *type : types)
            result.push_back(translateType(type));
    }

    mlir::Type PatchIRCodegen::translateType(llvm::Type *ty) {
        if (auto sty = llvm::dyn_cast< llvm::StructType >(ty)) {
            if (sty->hasName()) {
                llvm::SmallVector< mlir::Type, 8 > subtypes;
                auto id = mlir::LLVM::LLVMStructType::getIdentified(
                    &this->mlir_context, sty->getName());
                if (!id.isInitialized()) {
                    translateTypes(sty->subtypes(), subtypes);
                    auto res = id.setBody(subtypes, sty->isPacked());
                    if (res.succeeded()) {
                        return id;
                    }
                } else {
                    return id;
                }
            }
        }
        return this->llvm_to_mlir_type.translateType(ty);
    }

    mlir::Attribute PatchIRCodegen::CreatePatchIRValue(const anvill::ValueDecl &decl) {
        if (decl.ordered_locs.size() != 1) {
            throw std::runtime_error("Cannot currently handle compound valuedecls");
        }

        auto &loc = decl.ordered_locs[0];
        return CreateLowLoc(loc);
    }

    void PatchIRCodegen::CreateParam(
        const anvill::BasicBlockVariable &bb_param,
        std::vector< mlir::Value > &param_locs,
        mlir::Block &where) {
        auto loc_attr = this->CreatePatchIRValue(bb_param.param);

        mlir::OpBuilder mlir_builder(&mlir_context);
        auto unk_loc = mlir_builder.getUnknownLoc();
        mlir_builder.setInsertionPointToEnd(&where);

        mlir::Attribute at_entry = bb_param.live_at_entry ? loc_attr : nullptr;
        mlir::Attribute at_exit  = bb_param.live_at_exit ? loc_attr : nullptr;

        auto valueop = mlir_builder.create< irene3::patchir::ValueOp >(
            unk_loc,
            irene3::patchir::LowValuePointerType::get(
                &this->mlir_context, this->translateType(bb_param.param.type)),
            StringAttr(bb_param.param.name), at_entry, at_exit);

        param_locs.push_back(valueop);
    }

    std::vector< mlir::Attribute > PatchIRCodegen::BuildSOffsetVector(
        const std::vector< anvill::OffsetDomain > offsets) {
        std::vector< mlir::Attribute > res;
        for (auto &symval : offsets) {
            auto value = this->CreatePatchIRValue(symval.target_value);
            if (auto v = mlir::dyn_cast< patchir::RegisterAttr >(value)) {
                res.push_back(
                    patchir::StackOffsetAttr::get(&this->mlir_context, v, symval.stack_offset));
            }
        }

        return res;
    }

    void PatchIRCodegen::CreateBlockFunc(
        anvill::Uid buid,
        const anvill::CodeBlock &block,
        const anvill::BasicBlockContext &block_ctx,
        mlir::Block &where,
        const std::unordered_map< anvill::Uid, std::string > &repr_funcs) {
        auto res = repr_funcs.find(buid);
        if (res != repr_funcs.end()) {
            mlir::OpBuilder mlir_builder(&mlir_context);
            auto unk_loc = mlir_builder.getUnknownLoc();
            mlir_builder.setInsertionPointToEnd(&where);

            auto stack_entry
                = irene3::GetStackOffset(*spec.Arch(), block_ctx.GetStackOffsetsAtEntry());
            auto stack_exit
                = irene3::GetStackOffset(*spec.Arch(), block_ctx.GetStackOffsetsAtExit());

            std::vector< mlir::Attribute > soffset_entry
                = this->BuildSOffsetVector(block_ctx.GetStackOffsetsAtEntry().affine_equalities);
            std::vector< mlir::Attribute > soffset_exit
                = this->BuildSOffsetVector(block_ctx.GetStackOffsetsAtExit().affine_equalities);

            auto regionop = mlir_builder.create< irene3::patchir::RegionOp >(
                unk_loc, block.addr, buid.value, block.size, stack_entry, stack_exit,
                mlir::ArrayAttr::get(&this->mlir_context, soffset_entry),
                mlir::ArrayAttr::get(&this->mlir_context, soffset_exit));
            auto &region_body = regionop.getBody().emplaceBlock();

            std::vector< mlir::Value > param_locs;
            for (auto &bb_param : block_ctx.LiveParamsAtEntryAndExit()) {
                CreateParam(bb_param, param_locs, region_body);
            }

            mlir_builder.setInsertionPointToEnd(&region_body);
            mlir_builder.create< irene3::patchir::CallOp >(
                unk_loc, SymbolRefAttr(res->second), param_locs);
        }
    }

} // namespace irene3
