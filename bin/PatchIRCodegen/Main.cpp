#include <anvill/Declarations.h>
#include <anvill/Optimize.h>
#include <anvill/Providers.h>
#include <anvill/Specification.h>
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
#include <irene3/TypeDecoder.h>
#include <irene3/Util.h>
#include <irene3/Version.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/raw_ostream.h>
#include <mlir/Dialect/DLTI/DLTI.h>
#include <mlir/Dialect/LLVMIR/LLVMDialect.h>
#include <mlir/IR/Attributes.h>
#include <mlir/IR/Builders.h>
#include <mlir/IR/BuiltinOps.h>
#include <mlir/IR/BuiltinTypes.h>
#include <mlir/IR/DialectRegistry.h>
#include <mlir/IR/MLIRContext.h>
#include <mlir/IR/OperationSupport.h>
#include <mlir/IR/Verifier.h>
#include <mlir/Target/LLVMIR/Import.h>
#include <remill/BC/Error.h>
#include <remill/BC/Util.h>
#include <unordered_map>
#include <unordered_set>

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

            if (!llvm::isLifetimeIntrinsic(intrinsic->getIntrinsicID())) {
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
    std::unordered_map< uint64_t, std::vector< irene3::GlobalVarInfo > > gvars;

    mlir::MLIRContext& mlir_context;
    anvill::Specification spec;
    mlir::OwningOpRef< mlir::ModuleOp > mlir_module;
    mlir::LLVM::LLVMPointerType ptr_type;
    anvill::SpecBlockContexts block_contexts;

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

                for (auto var : irene3::UsedGlobalValue< llvm::GlobalVariable >(
                         func, spec.GetRequiredGlobals())) {
                    auto pc_metadata = irene3::GetPCMetadata(var);
                    if (!pc_metadata) {
                        continue;
                    }
                    auto v = spec.VariableAt(*pc_metadata);
                    if (v) {
                        size_t sz = v->type->getScalarSizeInBits();
                        gvars[decl->address].push_back({ var->getName().str(), *pc_metadata, sz });
                    }
                }
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
        removeIntrinsics(*llvm_module);

        return llvm_module;
    }

    anvill::Specification DecodeSpec(std::istream& spec_stream) {
        auto maybe_spec = anvill::Specification::DecodeFromPB(llvm_context, spec_stream);
        CHECK(maybe_spec.Succeeded()) << maybe_spec.TakeError();
        return maybe_spec.TakeValue();
    }

    auto StringAttr(const auto& str) { return mlir::StringAttr::get(&mlir_context, str); }

    auto SymbolRefAttr(const auto& str) { return mlir::SymbolRefAttr::get(&mlir_context, str); }

    mlir::Attribute CreateLowLoc(const anvill::LowLoc& loc) {
        if (loc.reg) {
            return irene3::patchir::RegisterAttr::get(
                &mlir_context, StringAttr(loc.reg->name), loc.Size());
        } else if (loc.mem_reg) {
            return irene3::patchir::MemoryIndirectAttr::get(
                &mlir_context, StringAttr(loc.mem_reg->name), loc.mem_offset, loc.Size());
        } else {
            return irene3::patchir::MemoryAttr::get(&mlir_context, loc.mem_offset, loc.Size());
        }
    }

    auto CreateParam(
        const anvill::BasicBlockVariable& bb_param,
        std::vector< mlir::Value >& param_locs,
        mlir::Block& where) {
        if (bb_param.param.oredered_locs.size() != 1) {
            return;
        }

        mlir::OpBuilder mlir_builder(&mlir_context);
        auto unk_loc = mlir_builder.getUnknownLoc();
        mlir_builder.setInsertionPointToEnd(&where);

        auto& loc = bb_param.param.oredered_locs[0];

        mlir::Attribute at_entry = bb_param.live_at_entry ? CreateLowLoc(loc) : nullptr;
        mlir::Attribute at_exit  = bb_param.live_at_exit ? CreateLowLoc(loc) : nullptr;

        auto valueop = mlir_builder.create< irene3::patchir::ValueOp >(
            unk_loc, ptr_type, StringAttr(bb_param.param.name), at_entry, at_exit);

        param_locs.push_back(valueop);
    }

    auto CreateBlockFunc(
        uint64_t func_addr,
        const anvill::CodeBlock& block,
        const anvill::BasicBlockContext& block_ctx,
        const std::vector< mlir::Value >& gvars,
        mlir::Block& where) {
        mlir::OpBuilder mlir_builder(&mlir_context);
        auto unk_loc = mlir_builder.getUnknownLoc();
        mlir_builder.setInsertionPointToEnd(&where);

        auto stack_entry = irene3::GetStackOffset(*spec.Arch(), block_ctx.GetStackOffsetsAtEntry());
        auto stack_exit  = irene3::GetStackOffset(*spec.Arch(), block_ctx.GetStackOffsetsAtExit());
        auto regionop    = mlir_builder.create< irene3::patchir::RegionOp >(
            unk_loc, block.addr, block.size, stack_entry, stack_exit);
        auto& region_body = regionop.getBody().emplaceBlock();

        std::vector< mlir::Value > param_locs;
        for (auto& bb_param : block_ctx.LiveParamsAtEntryAndExit()) {
            CreateParam(bb_param, param_locs, region_body);
        }

        // Put the globals as the last passed arguments
        std::copy(gvars.begin(), gvars.end(), std::back_inserter(param_locs));

        std::stringstream llvm_func_name;
        llvm_func_name << "func" << func_addr << "basic_block" << block.addr;

        mlir_builder.setInsertionPointToEnd(&region_body);
        mlir_builder.create< irene3::patchir::CallOp >(
            unk_loc, SymbolRefAttr(llvm_func_name.str()), param_locs);
    }

  public:
    MLIRCodegen(mlir::MLIRContext& mlir_context, std::istream& spec_stream)
        : mlir_context(mlir_context)
        , spec(DecodeSpec(spec_stream))
        , mlir_module(mlir::translateLLVMIRToModule(LiftSpec(), &mlir_context))
        , ptr_type(mlir::LLVM::LLVMPointerType::get(&mlir_context))
        , block_contexts(spec.GetBlockContexts()) {
        spec.ForEachFunction([this](auto fdecl) {
            mlir::OpBuilder mlir_builder(&this->mlir_context);
            auto unk_loc = mlir_builder.getUnknownLoc();

            mlir_builder.setInsertionPointToEnd(mlir_module->getBody());
            auto funcop = mlir_builder.create< irene3::patchir::FunctionOp >(
                unk_loc, fdecl->address, StringAttr(symbol_map[fdecl->address]));
            auto& func_body = funcop.getBody().emplaceBlock();
            mlir_builder.setInsertionPointToEnd(&func_body);
            std::vector< mlir::Value > gvar_values;
            for (auto& gvar : gvars[fdecl->address]) {
                auto global_loc = irene3::patchir::MemoryAttr::get(
                    &this->mlir_context, gvar.address, gvar.size);
                gvar_values.push_back(mlir_builder.create< irene3::patchir::ValueOp >(
                    unk_loc, ptr_type, StringAttr(gvar.name), global_loc, global_loc));
            }

            for (auto& [uid, block] : fdecl->cfg) {
                const anvill::BasicBlockContext& block_ctx
                    = block_contexts.GetBasicBlockContextForUid(uid).value();
                CreateBlockFunc(fdecl->address, block, block_ctx, gvar_values, func_body);
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

    mlir_context.appendDialectRegistry(registry);

    std::ifstream spec_stream(FLAGS_spec);
    MLIRCodegen codegen(mlir_context, spec_stream);
    auto mlir_module = codegen.GetMLIRModule();

    if (FLAGS_mlir_out.empty()) {
        mlir_module->print(llvm::outs());
    } else {
        std::error_code ec;
        llvm::raw_fd_ostream os(FLAGS_mlir_out, ec);
        CHECK(!ec) << "Couldn't open output file `" << FLAGS_mlir_out << '`';
        mlir_module->print(os);
    }
}