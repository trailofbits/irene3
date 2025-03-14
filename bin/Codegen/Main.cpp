/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "codegen_common.h"

#include <filesystem>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <iostream>
#include <llvm/Support/JSON.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/raw_ostream.h>
#include <remill/BC/Error.h>
#include <sstream>
#include <unordered_set>

DEFINE_string(spec, "", "input spec");
DEFINE_string(output, "", "output patch file");
DEFINE_string(lift_list, "", "list of entities to lift");
DEFINE_bool(add_edges, false, "add outgoing edges to blocks for cfg construction");
DEFINE_bool(type_propagation, false, "output patch file");
DEFINE_bool(unsafe_stack_locations, false, "create separate locals for each stack location");
DEFINE_bool(h, false, "help");

DECLARE_bool(version);
DECLARE_bool(help);

int main(int argc, char* argv[]) {
    SetVersion();
    google::SetUsageMessage("IRENE3 codegen");
    google::ParseCommandLineNonHelpFlags(&argc, &argv, false);
    google::InitGoogleLogging(argv[0]);

    if (argc <= 1 || FLAGS_help || FLAGS_h) {
        google::ShowUsageWithFlagsRestrict(argv[0], __FILE__);
        return EXIT_FAILURE;
    }

    google::HandleCommandLineHelpFlags();

    auto maybe_buff = llvm::MemoryBuffer::getFileOrSTDIN(FLAGS_spec);
    if (remill::IsError(maybe_buff)) {
        std::cout << "Unable to read protobuf spec file '" << FLAGS_spec
                  << "': " << remill::GetErrorString(maybe_buff) << std::endl;
        return EXIT_FAILURE;
    }
    const std::unique_ptr< llvm::MemoryBuffer >& buff = remill::GetReference(maybe_buff);

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
        buff->getBuffer().str(), target_funcs, FLAGS_type_propagation, true,
        FLAGS_unsafe_stack_locations, FLAGS_add_edges, true);
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
