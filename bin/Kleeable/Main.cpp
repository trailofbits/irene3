/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Lifters.h>
#include <anvill/Optimize.h>
#include <anvill/Providers.h>
#include <anvill/Specification.h>
#include <clang/AST/GlobalDecl.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <iostream>
#include <irene3/DecompileSpec.h>
#include <irene3/TypeDecoder.h>
#include <irene3/Util.h>
#include <irene3/Version.h>
#include <llvm/ADT/Triple.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Value.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/MemoryBuffer.h>
#include <rellic/Decompiler.h>
#include <remill/BC/Error.h>
#include <remill/BC/Util.h>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <vector>

DEFINE_string(spec, "", "input spec");
DEFINE_string(ir_out, "", "LLVM IR output file");
DEFINE_string(lift_list, "", "list of entities to lift");
DEFINE_bool(no_lift_globals, false, "Dont' lift global variables");
DEFINE_bool(type_propagation, false, "Should propagate types to the decompiler");
DEFINE_bool(should_not_remove_anvill_pc, false, "Should remove anvill pc");
DEFINE_string(
    stub_name,
    "myread",
    "a stubbbed function to declare that initializes parameters to the entrypoint with symbolic "
    "bytes");
DEFINE_bool(
    initialize_stack_symbolically,
    false,
    "Mantains uninitiailized references into the stack that we coudl not eliminate");
DEFINE_bool(h, false, "help");
DEFINE_string(target_entrypoint, "", "Function name to stub");
DECLARE_bool(version);
DECLARE_bool(help);

namespace
{
    bool InitializeType(
        llvm::IRBuilder<>& bldr,
        llvm::Function* reader,
        llvm::Value* target_ptr,
        llvm::Type* elem_type,
        llvm::LLVMContext& context) {
        auto i32 = llvm::IntegerType::getInt32Ty(context);
        if (llvm::isa_and_nonnull< llvm::IntegerType >(elem_type)) {
            auto sz = llvm::ConstantInt::get(i32, elem_type->getPrimitiveSizeInBits() / 8, false);
            bldr.CreateCall(reader, { target_ptr, sz });
            return true;
        }

        if (auto* stype = llvm::dyn_cast< llvm::StructType >(elem_type)) {
            uint64_t ind = 0;
            for (auto fld : stype->elements()) {
                if (!InitializeType(
                        bldr, reader,
                        bldr.CreateGEP(
                            elem_type, target_ptr,
                            { llvm::ConstantInt::get(i32, 0), llvm::ConstantInt::get(i32, ind) }),
                        fld, context)) {
                    return false;
                }
                ind++;
            }

            return true;
        }

        if (auto* arr = llvm::dyn_cast< llvm::ArrayType >(elem_type)) {
            for (uint64_t ind = 0; ind < arr->getNumElements(); ind++) {
                if (!InitializeType(
                        bldr, reader,
                        bldr.CreateGEP(
                            elem_type, target_ptr,
                            { llvm::ConstantInt::get(i32, 0), llvm::ConstantInt::get(i32, ind) }),
                        arr->getElementType(), context)) {
                    return false;
                }
            }

            return true;
        }

        return false;
    }
} // namespace

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

    if (FLAGS_spec.empty()) {
        std::cerr << "Must specify input binary" << std::endl;
        return EXIT_FAILURE;
    }

    if (FLAGS_target_entrypoint.empty()) {
        std::cerr << "Must specify an entrypoint to stub " << std::endl;
        return EXIT_FAILURE;
    }

    if (FLAGS_stub_name.empty()) {
        std::cerr << "Must provide a name for the symbolic stub" << std::endl;
        return EXIT_FAILURE;
    }

    std::filesystem::path input_spec(FLAGS_spec);

    std::unordered_set< uint64_t > target_funcs;

    irene3::TypeDecoder type_decoder;
    auto maybe_spec = irene3::ProtobufPathToDecompilationBuilder(
        FLAGS_spec, FLAGS_type_propagation, /*args_as_locals=*/false, type_decoder);
    if (!maybe_spec.Succeeded()) {
        std::cerr << maybe_spec.TakeError() << std::endl;
        return EXIT_FAILURE;
    }

    auto builder = maybe_spec.TakeValue();
    if (!FLAGS_lift_list.empty()) {
        std::stringstream ss(FLAGS_lift_list);

        for (uint64_t addr; ss >> std::hex >> addr;) {
            target_funcs.insert(addr);
            LOG(INFO) << "Added target " << std::hex << addr;
            if (ss.peek() == ',') {
                ss.ignore();
            }
        }

        builder.target_funcs = target_funcs;
    }
    irene3::SpecDecompilationJob job(std::move(builder));

    if (!FLAGS_initialize_stack_symbolically) {
        job.stack_initialization_strategy
            = anvill::StackFrameStructureInitializationProcedure::kUndef;
    }
    job.should_remove_anvill_pc = !FLAGS_should_not_remove_anvill_pc;

    auto decomp_res = job.Decompile();
    if (!decomp_res.Succeeded()) {
        std::cerr << decomp_res.TakeError() << std::endl;
        return EXIT_FAILURE;
    }

    irene3::DecompilationResult decomp = decomp_res.TakeValue();

    llvm::Module* mod = decomp.mod.get();

    auto tgt_func = mod->getFunction(FLAGS_target_entrypoint);
    if (!tgt_func) {
        std::cerr << FLAGS_target_entrypoint << " not in target decomp" << std::endl;
        return EXIT_FAILURE;
    }

    auto func_ty = llvm::FunctionType::get(llvm::IntegerType::getInt32Ty(mod->getContext()), false);

    auto main_func = llvm::Function::Create(
        func_ty, llvm::GlobalValue::LinkageTypes::ExternalLinkage, "main", mod);

    auto stub_type = llvm::FunctionType::get(
        llvm::Type::getVoidTy(mod->getContext()),
        {
            llvm::PointerType::get(mod->getContext(), 0),
            llvm::IntegerType::getInt32Ty(mod->getContext()),
        },
        false);
    auto symbolic_stub = llvm::Function::Create(
        stub_type, llvm::GlobalValue::LinkageTypes::ExternalLinkage, FLAGS_stub_name, mod);

    auto block = llvm::BasicBlock::Create(mod->getContext(), "ent_block", main_func);

    llvm::IRBuilder<> bldr(block);
    std::vector< llvm::Value* > params;

    for (auto& prm : tgt_func->args()) {
        auto alloc = bldr.CreateAlloca(prm.getType());

        if (!prm.getType()->isSized()) {
            std::cerr << "Cannot generate stub call for unsized type: "
                      << remill::LLVMThingToString(prm.getType());
            return EXIT_FAILURE;
        }

        if (!InitializeType(bldr, symbolic_stub, alloc, prm.getType(), mod->getContext())) {
            std::cerr << "Could not initialize type " << remill::LLVMThingToString(stub_type);
        }

        params.push_back(bldr.CreateLoad(prm.getType(), alloc));
    }

    bldr.CreateCall(tgt_func, params);

    bldr.CreateRet(llvm::ConstantInt::get(llvm::IntegerType::getInt32Ty(mod->getContext()), 0));

    auto res = remill::VerifyModuleMsg(mod);
    if (res) {
        LOG(ERROR) << "module failed to verify: " << *res;
    }
    if (!FLAGS_ir_out.empty()) {
        if (!remill::StoreModuleIRToFile(mod, FLAGS_ir_out, true)) {
            std::cerr << "Could not save LLVM IR to " << FLAGS_ir_out << '\n';
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}
