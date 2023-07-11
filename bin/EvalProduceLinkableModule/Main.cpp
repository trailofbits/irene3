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
#include <filesystem>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <iostream>
#include <irene3/DecompileSpec.h>
#include <irene3/TypeDecoder.h>
#include <irene3/Util.h>
#include <irene3/Version.h>
#include <llvm/ADT/Triple.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalObject.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
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
DEFINE_string(csmith_ir_out, "", "LLVM IR output file");
DEFINE_string(decomp_ir_out, "", "LLVM IR output file");
DEFINE_string(csmith_module, "", "LLVM module of csmith");
DEFINE_string(fname, "", "Target function to replace");

DEFINE_bool(type_propagation, false, "Should propagate types to the decompiler");
DEFINE_bool(
    initialize_stack_symbolically,
    false,
    "Mantains uninitiailized references into the stack that we coudl not eliminate");
DEFINE_bool(h, false, "help");

DECLARE_bool(version);
DECLARE_bool(help);

namespace
{
    void ReplaceGlobalValueWithExtern(
        llvm::GlobalObject* target_value, llvm::GlobalObject* replace_with) {
        llvm::Module* curr = target_value->getParent();
        if (llvm::isa_and_nonnull< llvm::Function >(target_value)
            && llvm::isa_and_nonnull< llvm::Function >(replace_with)) {
            auto target_function = llvm::cast< llvm::Function >(target_value);
            auto repl_function   = llvm::cast< llvm::Function >(target_value);
            std::string nm       = std::string(repl_function->getName());
            auto nfunc           = llvm::Function::Create(
                repl_function->getFunctionType(), llvm::GlobalValue::ExternalLinkage,
                repl_function->getName(), curr);

            target_function->replaceAllUsesWith(nfunc);
            target_function->eraseFromParent();
            nfunc->setName(nm);

        } else if (
            llvm::isa_and_nonnull< llvm::GlobalVariable >(target_value)
            && llvm::isa_and_nonnull< llvm::GlobalVariable >(replace_with)) {
            auto target_var = llvm::cast< llvm::GlobalVariable >(target_value);
            auto repl_var   = llvm::cast< llvm::GlobalVariable >(target_value);
            std::string nm  = std::string(repl_var->getName());
            auto newv       = new llvm::GlobalVariable(
                *curr, repl_var->getValueType(), repl_var->isConstant(),
                llvm::GlobalValue::ExternalLinkage, nullptr, "", target_var,
                repl_var->getThreadLocalMode(), repl_var->getAddressSpace(), true);
            target_var->replaceAllUsesWith(newv);
            target_var->eraseFromParent();
            newv->setName(nm);
        } else {
            return;
        }

        replace_with->setLinkage(llvm::GlobalValue::ExternalLinkage);
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
    google::SetUsageMessage("IRENE3 eval");
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

    if (FLAGS_csmith_module.empty()) {
        std::cerr << "Must provide module to link against" << std::endl;
        return EXIT_FAILURE;
    }

    std::filesystem::path input_spec(FLAGS_spec);

    irene3::TypeDecoder type_decoder;
    auto maybe_spec = irene3::ProtobufPathToDecompilationBuilder(
        FLAGS_spec, FLAGS_type_propagation, /*args_as_locals=*/false,
        /*unsafe_stack_locations*/ false, type_decoder);
    if (!maybe_spec.Succeeded()) {
        std::cerr << maybe_spec.TakeError() << std::endl;
        return EXIT_FAILURE;
    }

    auto builder = maybe_spec.TakeValue();

    irene3::SpecDecompilationJob job(std::move(builder));

    if (!FLAGS_initialize_stack_symbolically) {
        job.stack_initialization_strategy
            = anvill::StackFrameStructureInitializationProcedure::kUndef;
    }

    job.state_initialization_strategy = anvill::StateStructureInitializationProcedure::kUndef;
    job.should_inline_basic_blocks    = true;

    auto decomp_res = job.DecompileToLLVM();
    if (!decomp_res) {
        std::cerr << "Anvill decomp failed" << std::endl;
        return EXIT_FAILURE;
    }

    auto csmithod = remill::LoadModuleFromFile(&decomp_res->getContext(), FLAGS_csmith_module);

    ReplaceGlobalValueWithExtern(
        csmithod->getFunction(FLAGS_fname), decomp_res->getFunction(FLAGS_fname));

    std::unordered_map< std::string, llvm::GlobalObject* > covered;
    for (auto& gobj : csmithod->global_objects()) {
        if (gobj.getName() != FLAGS_fname) {
            llvm::GlobalObject* o = &gobj;
            covered.insert({ std::string(gobj.getName()), o });
        }
    }

    std::vector< std::pair< llvm::GlobalObject*, llvm::GlobalObject* > > replacements;
    for (auto& gobj : decomp_res->global_objects()) {
        auto maybe_repl = covered.find(std::string(gobj.getName()));
        if (maybe_repl != covered.end()) {
            if (maybe_repl->second->getValueType() == gobj.getValueType()) {
                replacements.push_back({ &gobj, maybe_repl->second });
            }
        }
    }

    for (auto pr : replacements) {
        ReplaceGlobalValueWithExtern(pr.first, pr.second);
    }

    decomp_res->getFunction(FLAGS_fname)->setLinkage(llvm::GlobalValue ::ExternalLinkage);
    if (!FLAGS_decomp_ir_out.empty()) {
        if (!remill::StoreModuleIRToFile(&*decomp_res, FLAGS_decomp_ir_out, true)) {
            std::cerr << "Could not save LLVM IR to " << FLAGS_decomp_ir_out << '\n';
            return EXIT_FAILURE;
        }
    }

    if (!FLAGS_csmith_ir_out.empty()) {
        if (!remill::StoreModuleIRToFile(&*csmithod, FLAGS_csmith_ir_out, true)) {
            std::cerr << "Could not save LLVM IR to " << FLAGS_csmith_ir_out << '\n';
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}
