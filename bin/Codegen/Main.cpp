/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "codegen_common.h"

#include <anvill/ABI.h>
#include <anvill/Declarations.h>
#include <anvill/Lifters.h>
#include <anvill/Optimize.h>
#include <anvill/Providers.h>
#include <anvill/Specification.h>
#include <clang/AST/Expr.h>
#include <clang/AST/GlobalDecl.h>
#include <clang/AST/Stmt.h>
#include <clang/Basic/LLVM.h>
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
#include <optional>
#include <rellic/Decompiler.h>
#include <remill/Arch/Arch.h>
#include <remill/BC/Error.h>
#include <remill/BC/Util.h>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

DEFINE_string(spec, "", "input spec");
DEFINE_string(output, "", "output patch file");
DEFINE_string(lift_list, "", "list of entities to lift");
DEFINE_bool(add_edges, false, "add outgoing edges to blocks for cfg construction");
DEFINE_bool(type_propagation, false, "output patch file");
DEFINE_bool(unsafe_stack_locations, false, "create separate locals for each stack location");
DEFINE_bool(h, false, "help");

DECLARE_bool(version);
DECLARE_bool(help);

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
    auto maybe_result = ProcessSpecification(
        input_spec, target_funcs, FLAGS_type_propagation, true, FLAGS_unsafe_stack_locations,
        FLAGS_add_edges);
    if (!maybe_result.Succeeded()) {
        std::cerr << maybe_result.TakeError() << std::endl;
        return EXIT_FAILURE;
    }
    auto result = maybe_result.TakeValue();

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
