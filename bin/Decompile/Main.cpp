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
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/TargetParser/Triple.h>
#include <rellic/Decompiler.h>
#include <remill/BC/Error.h>
#include <remill/BC/Util.h>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

DEFINE_string(spec, "", "input spec");
DEFINE_string(ir_out, "", "LLVM IR output file");
DEFINE_string(bc_out, "", "LLVM Bitcode output file");
DEFINE_string(c_out, "", "C output file");
DEFINE_string(lift_list, "", "list of entities to lift");
DEFINE_bool(no_lift_globals, false, "Dont' lift global variables");
DEFINE_bool(type_propagation, false, "Should propagate types to the decompiler");
DEFINE_bool(
    initialize_stack_symbolically,
    false,
    "Mantains uninitiailized references into the stack that we coudl not eliminate");
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

int main(int argc, char *argv[]) {
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
        std::cerr << "Must specify input specification" << std::endl;
        return EXIT_FAILURE;
    }

    std::filesystem::path input_spec(FLAGS_spec);
    std::filesystem::path output_file(FLAGS_c_out);

    std::unordered_set< uint64_t > target_funcs;

    irene3::TypeDecoder type_decoder;
    auto maybe_spec = irene3::ProtobufPathToDecompilationBuilder(
        input_spec, FLAGS_type_propagation, /*args_as_locals=*/false,
        /*unsafe_stack_locations*/ false, type_decoder);
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

    auto decomp_res = job.Decompile();
    if (!decomp_res.Succeeded()) {
        std::cerr << decomp_res.TakeError() << std::endl;
        return EXIT_FAILURE;
    }

    irene3::DecompilationResult decomp = decomp_res.TakeValue();

    if (!FLAGS_ir_out.empty()) {
        if (!remill::StoreModuleIRToFile(&*decomp.mod, FLAGS_ir_out, true)) {
            std::cerr << "Could not save LLVM IR to " << FLAGS_ir_out << '\n';
            return EXIT_FAILURE;
        }
    }
    if (!FLAGS_bc_out.empty()) {
        if (!remill::StoreModuleToFile(&*decomp.mod, FLAGS_bc_out, true)) {
            std::cerr << "Could not save LLVM bitcode to " << FLAGS_bc_out << '\n';
            return EXIT_FAILURE;
        }
    }

    if (!FLAGS_c_out.empty()) {
        std::error_code ec;
        llvm::raw_fd_ostream output(FLAGS_c_out, ec);
        if (ec) {
            std::cerr << "Could not open output file " << FLAGS_c_out << std::endl;
            return EXIT_FAILURE;
        }

        decomp.ast->getASTContext().getTranslationUnitDecl()->print(output);
    }

    return EXIT_SUCCESS;
}
