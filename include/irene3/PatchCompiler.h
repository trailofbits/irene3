/*
 * Copyright (c) 2023-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <irene3/LowLocCCBuilder.h>
#include <irene3/PatchIR/PatchIRAttrs.h>
#include <irene3/PatchIR/PatchIRDialect.h>
#include <irene3/PatchIR/PatchIROps.h>
#include <llvm/CodeGen/TargetRegisterInfo.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/Support/raw_ostream.h>
#include <memory>
#include <mlir/IR/BuiltinOps.h>
#include <mlir/IR/MLIRContext.h>
#include <optional>
#include <vector>

namespace irene3
{

    struct PatchMetada {
        std::optional< std::string > image_base_reg;
        std::vector< std::string > free_regs;
        uint64_t patch_offset;
    };

    class PatchCompiler {
      private:
        llvm::LLVMContext context;
        mlir::MLIRContext &mlir_cont;
        std::string feature_string;
        std::string cpu;

      public:
        PatchCompiler(mlir::MLIRContext &mlir_cont, std::string feature_string, std::string cpu)
            : mlir_cont(mlir_cont)
            , feature_string(std::move(feature_string))
            , cpu(std::move(cpu)) {}

        void RewriteModuleToLLVM(mlir::Operation *op);

        const llvm::TargetSubtargetInfo &GetSubTargetForRegion(
            irene3::patchir::RegionOp &region, llvm::TargetMachine *tm);

        PatchMetada OptimizeIntoCompileableLLVM(
            llvm::Module *,
            ModuleCallingConventions &cconcv,
            mlir::ModuleOp,
            const llvm::TargetRegisterInfo *rinfo);

        std::pair< std::unique_ptr< llvm::Module >, llvm::Function * > CreateLLVMModForRegion(
            irene3::patchir::RegionOp &region);
        PatchMetada Compile(irene3::patchir::RegionOp &, llvm::raw_pwrite_stream &os);
    };
} // namespace irene3