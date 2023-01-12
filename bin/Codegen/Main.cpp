/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
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
#include <clang/Tooling/Tooling.h>
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
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/raw_ostream.h>
#include <rellic/Decompiler.h>
#include <remill/BC/Error.h>
#include <remill/BC/Util.h>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>

DEFINE_string(spec, "", "input spec");
DEFINE_string(output, "", "output patch file");
DEFINE_string(lift_list, "", "list of entities to lift");
DEFINE_bool(type_propagation, false, "output patch file");
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

template< typename T >
std::string to_hex(T &&value) {
    std::stringstream ss;
    ss << "0x" << std::hex << std::forward< T >(value);
    return ss.str();
}

int main(int argc, char *argv[]) {
    SetVersion();
    google::SetUsageMessage("IRENE3 codegen");
    google::ParseCommandLineNonHelpFlags(&argc, &argv, false);
    google::InitGoogleLogging(argv[0]);

    if (argc <= 1 || FLAGS_help || FLAGS_h) {
        google::ShowUsageWithFlagsRestrict(argv[0], __FILE__);
        return EXIT_FAILURE;
    }

    google::HandleCommandLineHelpFlags();

    std::filesystem::path input_spec(FLAGS_spec);
    std::filesystem::path output_file(FLAGS_output);

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
    auto decomp_res = job.DecompileBlocks();
    if (!decomp_res.Succeeded()) {
        std::cerr << decomp_res.TakeError() << std::endl;
        return EXIT_FAILURE;
    }

    auto block_contexts = builder.GetSpec().GetBlockContexts();
    llvm::json::Array patches;

    for (auto &[addr, compound] : decomp_res.Value().blocks) {
        const anvill::BasicBlockContext &block
            = block_contexts.GetBasicBlockContextForAddr(addr).value();

        llvm::json::Object patch;
        patch["patch-name"] = "block_" + std::to_string(addr);
        patch["patch-addr"] = to_hex(addr);

        std::string code;
        llvm::raw_string_ostream os(code);
        for (auto &stmt : compound->body()) {
            stmt->printPretty(os, nullptr, { {} });
            if (clang::isa< clang::Expr >(stmt)) {
                os << ";\n";
            }
        }
        patch["patch-code"] = code;

        llvm::json::Array patch_vars;
        for (auto &bb_param : block.LiveParamsAtEntryAndExit()) {
            auto var_spec = bb_param.param;
            llvm::json::Object var;
            var["name"] = var_spec.name;
            if (var_spec.reg) {
                if (bb_param.live_at_entry) {
                    var["at-entry"] = var_spec.reg->name;
                }

                if (bb_param.live_at_exit) {
                    var["at-exit"] = var_spec.reg->name;
                }
            } else if (var_spec.mem_reg) {
                llvm::json::Object memory;
                memory["frame-pointer"] = var_spec.mem_reg->name;
                memory["offset"]        = to_hex(var_spec.mem_offset) + ":"
                                   + std::to_string(var_spec.type->getScalarSizeInBits());
                var["memory"] = std::move(memory);
            } else {
                llvm::json::Object memory;
                memory["address"] = to_hex(var_spec.mem_offset) + ":"
                                    + std::to_string(var_spec.type->getScalarSizeInBits());
                var["memory"] = std::move(memory);
            }
            patch_vars.push_back(std::move(var));
        }

        patch["patch-vars"] = std::move(patch_vars);
        patches.push_back(std::move(patch));
    }

    llvm::json::Object result;
    result["patches"] = std::move(patches);

    if (!FLAGS_output.empty()) {
        std::error_code ec;
        llvm::raw_fd_ostream output(FLAGS_output, ec);
        if (ec) {
            std::cerr << "Could not open output file " << FLAGS_output << std::endl;
            return EXIT_FAILURE;
        }

        output << llvm::json::Value(std::move(result));
    }

    return EXIT_SUCCESS;
}
