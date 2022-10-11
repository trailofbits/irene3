/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "JsonDecompBuilder.h"

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
#include <irene3/Util.h>
#include <irene3/Version.h>
#include <llvm/ADT/Triple.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/raw_ostream.h>
#include <pasta/AST/Printer.h>
#include <pasta/AST/Token.h>
#include <rellic/Decompiler.h>
#include <remill/BC/Error.h>
#include <remill/BC/Util.h>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

DEFINE_string(spec, "", "input spec");
DEFINE_bool(type_propagation, false, "Propagate spec types to decompiler");

int main(int argc, char *argv[]) {
    google::SetUsageMessage("IRENE3 UITool");
    google::ParseCommandLineNonHelpFlags(&argc, &argv, false);
    google::InitGoogleLogging(argv[0]);

    google::HandleCommandLineHelpFlags();

    if (FLAGS_spec.empty()) {
        std::cerr << "Must specify input binary" << std::endl;
        return EXIT_FAILURE;
    }

    auto maybe_spec
        = irene3::ProtobufPathToDecompilationBuilder(FLAGS_spec, FLAGS_type_propagation);
    if (!maybe_spec.Succeeded()) {
        std::cerr << maybe_spec.TakeError() << std::endl;
        return EXIT_FAILURE;
    }

    irene3::SpecDecompilationJob job(maybe_spec.TakeValue());

    auto decomp_res = job.Decompile();
    if (!decomp_res.Succeeded()) {
        std::cerr << decomp_res.TakeError() << std::endl;
        return EXIT_FAILURE;
    }

    irene3::DecompilationResult decomp = decomp_res.TakeValue();

    JsonDecompBuilder builder(decomp);
    builder.WriteOut(llvm::outs());

    return EXIT_SUCCESS;
}
