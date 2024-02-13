#include "irene3/IreneLoweringInterface.h"

#include <algorithm>
#include <anvill/ABI.h>
#include <anvill/Declarations.h>
#include <anvill/Utils.h>
#include <cctype>
#include <functional>
#include <glog/logging.h>
#include <iostream>
#include <irene3/LowLocCCBuilder.h>
#include <irene3/PatchCompiler.h>
#include <irene3/PatchIR/PatchIRAttrs.h>
#include <irene3/PatchIR/PatchIROps.h>
#include <irene3/PhysicalLocationDecoder.h>
#include <irene3/Targets/Backend.h>
#include <irene3/Targets/ExplicitMappingBackend.h>
#include <irene3/Targets/GenericBackend.h>
#include <irene3/Transforms/RemoveUnusedStackValueOperands.h>
#include <irene3/Transforms/ReplaceRelReferences.h>
#include <irene3/Transforms/WrapFunctionWithMachineWrapper.h>
#include <irene3/Util.h>
#include <iterator>
#include <llvm/ADT/StringRef.h>
#include <llvm/ADT/StringSwitch.h>
#include <llvm/CodeGen/CallingConvLower.h>
#include <llvm/CodeGen/MachineFunction.h>
#include <llvm/CodeGen/TargetRegisterInfo.h>
#include <llvm/CodeGen/TargetSubtargetInfo.h>
#include <llvm/IR/Attributes.h>
#include <llvm/IR/CallingConv.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/PrintPasses.h>
#include <llvm/MC/CCRegistry.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCRegister.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Passes/OptimizationLevel.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/Alignment.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/CodeGen.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Target/TargetOptions.h>
#include <llvm/TargetParser/Triple.h>
#include <memory>
#include <mlir/Conversion/LLVMCommon/TypeConverter.h>
#include <mlir/Dialect/LLVMIR/LLVMAttrs.h>
#include <mlir/Dialect/LLVMIR/LLVMDialect.h>
#include <mlir/IR/Attributes.h>
#include <mlir/IR/BuiltinAttributes.h>
#include <mlir/IR/BuiltinOps.h>
#include <mlir/IR/Dialect.h>
#include <mlir/IR/MLIRContext.h>
#include <mlir/IR/OpDefinition.h>
#include <mlir/IR/Operation.h>
#include <mlir/IR/PatternMatch.h>
#include <mlir/IR/Value.h>
#include <mlir/IR/Visitors.h>
#include <mlir/Pass/PassManager.h>
#include <mlir/Pass/PassOptions.h>
#include <mlir/Pass/PassRegistry.h>
#include <mlir/Support/LLVM.h>
#include <mlir/Support/LogicalResult.h>
#include <mlir/Target/LLVMIR/Export.h>
#include <mlir/Target/LLVMIR/Import.h>
#include <mlir/Target/LLVMIR/LLVMTranslationInterface.h>
#include <mlir/Transforms/DialectConversion.h>
#include <optional>
#include <remill/BC/Util.h>
#include <string>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

/// todo rearch to a set of analyses and passes, analyses/pass extracts CC def
// then rewrite to llvm, then apply pass to llvm
// then run compiler toolchain

namespace irene3
{

    namespace
    {
        struct TranslateFunction : public mlir::ConversionPattern {
            TranslateFunction(mlir::MLIRContext *ctx)
                : mlir::ConversionPattern(irene3::patchir::FunctionOp::getOperationName(), 1, ctx) {
            }

            virtual mlir::LogicalResult matchAndRewrite(
                mlir::Operation *op,
                mlir::ArrayRef< mlir::Value > operands,
                mlir::ConversionPatternRewriter &rewriter) const override {
                rewriter.eraseOp(op);
                return mlir::LogicalResult::success();
            }
        };

        struct RemoveIreneGlobals : public mlir::ConversionPattern {
            RemoveIreneGlobals(mlir::MLIRContext *ctx)
                : mlir::ConversionPattern(irene3::patchir::Global::getOperationName(), 1, ctx) {}

            virtual mlir::LogicalResult matchAndRewrite(
                mlir::Operation *op,
                mlir::ArrayRef< mlir::Value > operands,
                mlir::ConversionPatternRewriter &rewriter) const override {
                rewriter.eraseOp(op);
                return mlir::LogicalResult::success();
            }
        };

    } // namespace

    std::unique_ptr< llvm::TargetMachine > BuildMachine(
        const llvm::Triple &triple, llvm::StringRef features, llvm::StringRef cpu) {
        std::string err;
        llvm::TargetOptions options;

        llvm::InitializeAllTargets();
        llvm::InitializeAllAsmPrinters();
        llvm::InitializeAllTargetMCs();

        auto tgt = llvm::TargetRegistry::lookupTarget(triple.str().c_str(), err);
        CHECK(tgt);
        auto target_machine = tgt->createTargetMachine(
            triple.getTriple(), cpu, features, options, llvm::Reloc::PIC_);

        return std::unique_ptr< llvm::TargetMachine >(target_machine);
    }

    std::optional< std::string > targetFunction(irene3::patchir::RegionOp &region) {
        CHECK(region.hasTrait< mlir::OpTrait::OneRegion >());
        for (auto c : region.getOps< irene3::patchir::CallOp >()) {
            return c.getCallee().str();
        }

        return std::nullopt;
    }

    void ExtractFunction(llvm::Function *old_func, llvm::Module *new_mod) {
        auto old_ty = old_func->getFunctionType();
        auto new_ty = llvm::cast< llvm::FunctionType >(
            remill::RecontextualizeType(old_ty, new_mod->getContext()));

        llvm::Function *new_func = llvm::Function::Create(
            new_ty, llvm::GlobalValue::ExternalLinkage, old_func->getName(), new_mod);
        remill::CloneFunctionInto(old_func, new_func);
        new_func->setMetadata(
            anvill::kBasicBlockUidMetadata, old_func->getMetadata(anvill::kBasicBlockUidMetadata));
    }

    std::pair< std::unique_ptr< llvm::Module >, llvm::Function * > PatchCompiler::
        CreateLLVMModForRegion(irene3::patchir::RegionOp &region) {
        auto target = targetFunction(region);
        CHECK(target.has_value());

        auto orig_mod = region->getParentOp()->getParentOp();
        std::unordered_map< std::string, anvill::Uid > nm_to;
        std::unordered_map< std::string, uint64_t > func_name_to_pc;
        for (auto f : mlir::cast< mlir::ModuleOp >(orig_mod)
                          .getBodyRegion()
                          .getOps< irene3::patchir::FunctionOp >()) {
            func_name_to_pc.insert({ f.getNameAttr().str(), f.getAddress() });
            for (auto r : f.getOps< irene3::patchir::RegionOp >()) {
                auto call   = *r.getOps< irene3::patchir::CallOp >().begin();
                auto callee = call.getCallee();
                nm_to.insert({ callee.str(), { r.getUid() } });
            }
        }

        this->RewriteModuleToLLVM(orig_mod);
        auto mod = mlir::translateModuleToLLVMIR(orig_mod, this->context);

        // hack to reaatach uid
        for (const auto &[k, v] : nm_to) {
            auto uid_val = llvm::ConstantInt::get(llvm::Type::getInt64Ty(this->context), v.value);
            auto uid_md  = llvm::ValueAsMetadata::get(uid_val);
            mod->getFunction(k)->setMetadata(
                anvill::kBasicBlockUidMetadata, llvm::MDNode::get(context, uid_md));
        }

        auto tfunc = mod->getFunction(*target);
        CHECK(tfunc);

        auto module = std::make_unique< llvm::Module >("lifted_code", this->context);
        module->setDataLayout(mod->getDataLayout());
        module->setTargetTriple(mod->getTargetTriple());
        ExtractFunction(tfunc, module.get());

        for (const auto &[k, v] : func_name_to_pc) {
            auto tf = module->getFunction(k);
            if (tf) {
                irene3::SetPCMetadata(tf, v);
            }
        }

        return std::make_pair(std::move(module), module->getFunction(tfunc->getName()));
    }

    PatchMetada PatchCompiler::OptimizeIntoCompileableLLVM(
        llvm::Module *mod,
        ModuleCallingConventions &cconv,
        mlir::ModuleOp mlirmod,
        const llvm::TargetRegisterInfo *reg_info,
        const IreneLoweringInterface &backend) {
        llvm::PassBuilder pb;

        // Remove Globals
        for (auto glob : mlirmod.getOps< patchir::Global >()) {
            auto gv = mod->getGlobalVariable(glob.getTargetSymName());
            if (gv) {
                gv->setInitializer(nullptr);
                gv->setLinkage(llvm::GlobalValue::ExternalLinkage);
            }
        }

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
        WrapFunctionWithMachineWrapper wrapper(
            mod->getContext(), mlirmod, reg_info, cconv, backend);
        wrapper.run(*mod, mam);
        ReplaceRelReferences refs(mod->getContext(), mlirmod, reg_info, cconv, backend);
        refs.run(*mod, mam);

        auto regs_list = refs.getFreeRegsList();

        std::vector< std::string > res;
        std::transform(
            regs_list.begin(), regs_list.end(), std::back_inserter(res),
            [](const irene3::patchir::RegisterAttr &reg) { return reg.getReg().str(); });

        PatchMetada stor = { refs.GetImageBaseReg(), res, refs.GetBaseImage() };

        auto msg = remill::VerifyModuleMsg(mod);
        // mod->dump();
        if (msg) {
            LOG(FATAL) << "Wrapping failed: " << *msg;
        }

        // llvm::DebugFlag = true;
        auto pipeline = pb.buildModuleOptimizationPipeline(
            llvm::OptimizationLevel::O3, llvm::ThinOrFullLTOPhase::None);

        pipeline.run(*mod, mam);

        // mod->dump();

        // Manually clear the analyses to prevent ASAN failures in the destructors.
        mam.clear();
        fam.clear();
        cam.clear();
        lam.clear();

        return stor;
    }

    void PatchCompiler::RewriteModuleToLLVM(mlir::Operation *op) {
        mlir::RewritePatternSet rewrites(&this->mlir_cont);
        rewrites.add< TranslateFunction >(&this->mlir_cont);
        rewrites.add< RemoveIreneGlobals >(&this->mlir_cont);
        mlir::ConversionTarget target(this->mlir_cont);
        target.addLegalDialect< mlir::LLVM::LLVMDialect >();
        target.addLegalOp< mlir::ModuleOp >();
        auto res = mlir::applyFullConversion(op, target, std::move(rewrites));
        CHECK(res.succeeded());
    }

    std::unique_ptr< IreneLoweringInterface > PatchCompiler::BuildILI(
        const llvm::TargetSubtargetInfo &subtarget, const llvm::TargetRegisterInfo *rinfo) {
        if (!this->backend_name) {
            return std::make_unique< GenericBackend >(subtarget);
        }

        auto populated = Populate(*this->backend_name, subtarget, rinfo, context);
        if (!populated) {
            LOG(FATAL) << "Unsupported backend " << *this->backend_name;
        }
        return std::make_unique< irene3::ExplicitMappingBackend >(*populated);
    }

    const llvm::TargetSubtargetInfo &PatchCompiler::GetSubTargetForRegion(
        irene3::patchir::RegionOp &region, llvm::TargetMachine *tm) {
        auto tmp_mod = mlir::cast< mlir::ModuleOp >(region->getParentOp()->getParentOp()->clone());
        irene3::patchir::RegionOp found_r;
        for (auto f : tmp_mod.getOps< irene3::patchir::FunctionOp >()) {
            for (auto r : f.getOps< irene3::patchir::RegionOp >()) {
                if (r.getUid() == region.getUid()) {
                    found_r = r;
                }
            }
        }

        auto [mod, tgt_func] = CreateLLVMModForRegion(found_r);

        return tm->getSubtarget< llvm::TargetSubtargetInfo >(*tgt_func);
    }

    PatchMetada PatchCompiler::Compile(
        irene3::patchir::RegionOp &region, llvm::raw_pwrite_stream &os) {
        auto addr  = region.getAddress();
        auto modop = mlir::cast< mlir::ModuleOp >(region->getParentOp()->getParentOp());

        llvm::Triple triple(
            mlir::cast< mlir::StringAttr >(
                modop.getOperation()->getAttr(mlir::LLVM::LLVMDialect::getTargetTripleAttrName()))
                .str());

        auto tgt         = BuildMachine(triple, this->feature_string, this->cpu);
        auto &sub_target = GetSubTargetForRegion(region, tgt.get());

        auto reg_info = sub_target.getRegisterInfo();

        auto backend = this->BuildILI(sub_target, reg_info);

        auto mlirpm = mlir::PassManager::on< mlir::ModuleOp >(modop->getContext());
        mlirpm.addPass(std::make_unique< RemoveUnusedStackValueOperands >(*backend));
        auto res = mlirpm.run(modop.getOperation());
        CHECK(res.succeeded());
        modop->dump();

        modop->setAttr(
            mlir::LLVM::LLVMDialect::getDataLayoutAttrName(),
            mlir::StringAttr::get(&mlir_cont, tgt->createDataLayout().getStringRepresentation()));

        auto cloned_module = mlir::cast< mlir::ModuleOp >(modop->clone());
        ModuleCallingConventions cconv(cloned_module, *backend, this->context);
        llvm::legacy::PassManager pm;

        auto [mod, tgt_func] = CreateLLVMModForRegion(region);
        auto stor            = this->OptimizeIntoCompileableLLVM(
            mod.get(), cconv, cloned_module, sub_target.getRegisterInfo(), *backend);

        // cloned_module->dump();
        mod->dump();
        cconv.ApplyTo(mod.get());

        auto obj = std::make_unique< CCObjSelector >(cconv.BuildCConvMap());
        // llvm::DebugFlag    = false;
        // llvm::PrintChanged = llvm::ChangePrinter::Verbose;
        tgt->addPassesToEmitFile(pm, os, &llvm::errs(), llvm::CodeGenFileType::CGFT_AssemblyFile);
        // obj->dump();
        llvm::CCRegistry::registerCCOverrride(tgt->getTarget().getName(), std::move(obj));

        pm.run(*mod);
        // auto abi = BuildABIForRegion(region);
        // auto fop = mlir::cast< patchir::FunctionOp >(region->getParentOp());
        //  fop.getTar
        //  llvm::CCRegistry::registerCCOverrride("", std::unique_ptr< CCObj > Handler)

        return { stor.image_base_reg, stor.free_regs, addr - stor.patch_offset };
    }

} // namespace irene3