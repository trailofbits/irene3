#include <anvill/Declarations.h>
#include <anvill/Optimize.h>
#include <anvill/Providers.h>
#include <anvill/Specification.h>
#include <anvill/Type.h>
#include <anvill/Utils.h>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <iostream>
#include <irene3/DecompileSpec.h>
#include <irene3/PatchIR/PatchIRAttrs.h>
#include <irene3/PatchIR/PatchIRDialect.h>
#include <irene3/PatchIR/PatchIROps.h>
#include <irene3/PatchIR/PatchIRTypes.h>
#include <irene3/Transforms/RemoveProgramCounterAndMemory.h>
#include <irene3/TypeDecoder.h>
#include <irene3/Util.h>
#include <irene3/Version.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Passes/OptimizationLevel.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <memory>
#include <mlir/Dialect/DLTI/DLTI.h>
#include <mlir/Dialect/LLVMIR/LLVMDialect.h>
#include <mlir/Dialect/LLVMIR/LLVMTypes.h>
#include <mlir/IR/Attributes.h>
#include <mlir/IR/Builders.h>
#include <mlir/IR/BuiltinAttributes.h>
#include <mlir/IR/BuiltinOps.h>
#include <mlir/IR/BuiltinTypes.h>
#include <mlir/IR/DialectRegistry.h>
#include <mlir/IR/MLIRContext.h>
#include <mlir/IR/OperationSupport.h>
#include <mlir/IR/Verifier.h>
#include <mlir/Support/LLVM.h>
#include <mlir/Target/LLVMIR/Import.h>
#include <mlir/Target/LLVMIR/TypeFromLLVM.h>
#include <optional>
#include <remill/BC/Error.h>
#include <remill/BC/Util.h>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <variant>

DEFINE_string(spec, "", "input spec");
DEFINE_string(mlir_out, "", "MLIR output file");
DEFINE_string(lift_list, "", "list of entities to lift");
DEFINE_bool(h, false, "help");

DECLARE_bool(version);
DECLARE_bool(help);

static void SetVersion(void) {
    std::stringstream version;

    auto vs = irene3::Version::GetVersionString();
    if (0 == vs.size()) {
        vs = "unknown";
    }
    version << vs << "\n";
    if (!irene3::Version::HasVersionData()) {
        version << "No extended version information found!\n";
    } else {
        version << "Commit Hash: " << irene3::Version::GetCommitHash() << "\n";
        version << "Commit Date: " << irene3::Version::GetCommitDate() << "\n";
        version << "Last commit by: " << irene3::Version::GetAuthorName() << " ["
                << irene3::Version::GetAuthorEmail() << "]\n";
        version << "Commit Subject: [" << irene3::Version::GetCommitSubject() << "]\n";
        version << "\n";
        if (irene3::Version::HasUncommittedChanges()) {
            version << "Uncommitted changes were present during build.\n";
        } else {
            version << "All changes were committed prior to building.\n";
        }
    }
    version << "Using LLVM " << LLVM_VERSION_STRING << std::endl;

    google::SetVersionString(version.str());
}

// This function removes all of the lifetime intrinsics from an LLVM module.
//
// This is needed because such annotations are not supported by the LLVMIR dialect and cause issues
// during conversion.
static void removeIntrinsics(llvm::Module& mod) {
    std::vector< llvm::Instruction* > to_remove;
    for (auto& func : mod.functions()) {
        for (auto& inst : llvm::instructions(func)) {
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

class MLIRCodegen {
    llvm::LLVMContext llvm_context;
    std::unordered_map< uint64_t, std::string > symbol_map;
    std::unordered_map< std::string, irene3::GlobalVarInfo > gvars;

    mlir::MLIRContext& mlir_context;
    anvill::Specification spec;
    std::unique_ptr< llvm::Module > module;

    mlir::OwningOpRef< mlir::ModuleOp > mlir_module;
    mlir::LLVM::LLVMPointerType ptr_type;
    anvill::SpecBlockContexts block_contexts;
    mlir::LLVM::TypeFromLLVMIRTranslator llvm_to_mlir_type;

    void NameEntity(llvm::Constant* v, const anvill::EntityLifter& lifter) {
        if (auto addr = lifter.AddressOfEntity(v)) {
            if (auto el = symbol_map.find(*addr); el != symbol_map.end()) {
                v->setName(el->second);
            }
        }
    }

    std::unique_ptr< llvm::Module > LiftSpec() {
        CHECK(!FLAGS_spec.empty()) << "Must specify input binary";

        std::unordered_set< uint64_t > target_funcs;
        if (!FLAGS_lift_list.empty()) {
            std::stringstream ss(FLAGS_lift_list);

            for (uint64_t addr; ss >> std::hex >> addr;) {
                target_funcs.insert(addr);
                LOG(INFO) << "Added target " << std::hex << addr;
                if (ss.peek() == ',') {
                    ss.ignore();
                }
            }
        }

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

        spec.ForEachSymbol([this](uint64_t addr, const std::string& name) {
            symbol_map.emplace(addr, name);
            return true;
        });

        spec.ForEachFunction([this, &lifter, &target_funcs](auto decl) {
            llvm::Function* func;
            if (target_funcs.empty() || target_funcs.find(decl->address) != target_funcs.end()) {
                func = lifter.LiftEntity(*decl);
            } else {
                func = lifter.DeclareEntity(*decl);
            }

            NameEntity(func, lifter);
            return true;
        });

        spec.ForEachVariable([this, &lifter](auto decl) {
            llvm::Constant* cv = lifter.LiftEntity(*decl);

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

        for (auto& f : llvm_module->functions()) {
            auto uid = anvill::GetBasicBlockUid(&f);
            if (uid) {
                for (auto var : irene3::UsedGlobalValue< llvm::GlobalVariable >(
                         &f, spec.GetRequiredGlobals())) {
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

    anvill::Specification DecodeSpec(std::istream& spec_stream) {
        auto maybe_spec = anvill::Specification::DecodeFromPB(this->llvm_context, spec_stream);
        CHECK(maybe_spec.Succeeded()) << maybe_spec.TakeError();
        return maybe_spec.TakeValue();
    }

    auto StringAttr(const auto& str) { return mlir::StringAttr::get(&mlir_context, str); }

    auto SymbolRefAttr(const auto& str) { return mlir::SymbolRefAttr::get(&mlir_context, str); }

    mlir::Attribute CreateLowLoc(const anvill::LowLoc& loc) {
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

    auto CreateParam(
        const anvill::BasicBlockVariable& bb_param,
        std::vector< mlir::Value >& param_locs,
        mlir::Block& where) {
        if (bb_param.param.ordered_locs.size() != 1) {
            return;
        }

        mlir::OpBuilder mlir_builder(&mlir_context);
        auto unk_loc = mlir_builder.getUnknownLoc();
        mlir_builder.setInsertionPointToEnd(&where);

        auto& loc = bb_param.param.ordered_locs[0];

        mlir::Attribute at_entry = bb_param.live_at_entry ? CreateLowLoc(loc) : nullptr;
        mlir::Attribute at_exit  = bb_param.live_at_exit ? CreateLowLoc(loc) : nullptr;

        auto valueop = mlir_builder.create< irene3::patchir::ValueOp >(
            unk_loc,
            irene3::patchir::LowValuePointerType::get(
                &this->mlir_context, this->translateType(bb_param.param.type)),
            StringAttr(bb_param.param.name), at_entry, at_exit);

        param_locs.push_back(valueop);
    }

    auto CreateBlockFunc(
        anvill::Uid buid,
        const anvill::CodeBlock& block,
        const anvill::BasicBlockContext& block_ctx,
        mlir::Block& where,
        const std::unordered_map< anvill::Uid, std::string >& repr_funcs) {
        auto res = repr_funcs.find(buid);
        if (res != repr_funcs.end()) {
            mlir::OpBuilder mlir_builder(&mlir_context);
            auto unk_loc = mlir_builder.getUnknownLoc();
            mlir_builder.setInsertionPointToEnd(&where);

            auto stack_entry
                = irene3::GetStackOffset(*spec.Arch(), block_ctx.GetStackOffsetsAtEntry());
            auto stack_exit
                = irene3::GetStackOffset(*spec.Arch(), block_ctx.GetStackOffsetsAtExit());
            auto regionop = mlir_builder.create< irene3::patchir::RegionOp >(
                unk_loc, block.addr, buid.value, block.size, stack_entry, stack_exit);
            auto& region_body = regionop.getBody().emplaceBlock();

            std::vector< mlir::Value > param_locs;
            for (auto& bb_param : block_ctx.LiveParamsAtEntryAndExit()) {
                CreateParam(bb_param, param_locs, region_body);
            }

            mlir_builder.setInsertionPointToEnd(&region_body);
            mlir_builder.create< irene3::patchir::CallOp >(
                unk_loc, SymbolRefAttr(res->second), param_locs);
        }
    }

    void translateTypes(
        llvm::ArrayRef< llvm::Type* > types, llvm::SmallVectorImpl< mlir::Type >& result) {
        result.reserve(result.size() + types.size());
        for (llvm::Type* type : types)
            result.push_back(translateType(type));
    }

    mlir::Type translateType(llvm::Type* ty) {
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

  public:
    MLIRCodegen(mlir::MLIRContext& mlir_context, std::istream& spec_stream)
        : mlir_context(mlir_context)
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

        for (const auto& [nm, gv] : this->gvars) {
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
            auto& func_body = funcop.getBody().emplaceBlock();
            mlir_builder.setInsertionPointToEnd(&func_body);

            std::unordered_map< anvill::Uid, std::string > repr_funcs;
            for (llvm::Function& f : module->functions()) {
                auto addr = anvill::GetBasicBlockUid(&f);
                if (addr) {
                    repr_funcs.insert({ *addr, f.getName().str() });
                }
            }

            for (auto& [uid, block] : fdecl->cfg) {
                const anvill::BasicBlockContext& block_ctx
                    = block_contexts.GetBasicBlockContextForUid(uid).value();

                CreateBlockFunc(uid, block, block_ctx, func_body, repr_funcs);
            }

            return true;
        });
        CHECK(mlir_module->verify().succeeded());
    }

    llvm::LLVMContext& GetLLVMContext() { return llvm_context; }

    anvill::Specification& GetSpecification() { return spec; }

    mlir::OwningOpRef< mlir::ModuleOp > GetMLIRModule() { return std::move(mlir_module); }
};

int main(int argc, char* argv[]) {
    SetVersion();
    google::SetUsageMessage("IRENE3 decompiler");
    google::ParseCommandLineNonHelpFlags(&argc, &argv, false);
    google::InitGoogleLogging(argv[0]);

    if (argc <= 1 || FLAGS_help || FLAGS_h) {
        google::ShowUsageWithFlagsRestrict(argv[0], __FILE__);
        return EXIT_FAILURE;
    }

    google::HandleCommandLineHelpFlags();

    mlir::MLIRContext mlir_context;

    mlir::DialectRegistry registry;
    registry.insert< irene3::patchir::PatchIRDialect >();
    registry.insert< mlir::LLVM::LLVMDialect >();
    registry.insert< mlir::DLTIDialect >();

    //    mlir_context.getOrLoadDialect< irene3::patchir::PatchIRDialect >();
    //  mlir_context.getOrLoadDialect< mlir::LLVM::LLVMDialect >();
    // mlir_context.getOrLoadDialect< mlir::DLTIDialect >();
    mlir_context.appendDialectRegistry(registry);
    std::ifstream spec_stream(FLAGS_spec);
    MLIRCodegen codegen(mlir_context, spec_stream);
    auto mlir_module = codegen.GetMLIRModule();
    CHECK(mlir_module->verify().succeeded());
    if (FLAGS_mlir_out.empty()) {
        mlir_module->print(llvm::outs());
    } else {
        std::error_code ec;
        llvm::raw_fd_ostream os(FLAGS_mlir_out, ec);
        CHECK(!ec) << "Couldn't open output file `" << FLAGS_mlir_out << '`';
        mlir_module->print(os);
    }
}
