/*
 * Copyright (c) 2023-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include "irene3/IreneLoweringInterface.h"

#include <irene3/LowLocCCBuilder.h>
#include <irene3/PatchIR/PatchIRAttrs.h>
#include <irene3/PatchIR/PatchIRDialect.h>
#include <irene3/PatchIR/PatchIROps.h>
#include <llvm/CodeGen/TargetRegisterInfo.h>
#include <llvm/CodeGen/TargetSubtargetInfo.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/Passes/OptimizationLevel.h>
#include <llvm/Support/raw_ostream.h>
#include <memory>
#include <mlir/IR/BuiltinOps.h>
#include <mlir/IR/MLIRContext.h>
#include <optional>
#include <string>
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
        std::optional< std::string > backend_name;
        llvm::OptimizationLevel opt_level;

        std::unique_ptr< IreneLoweringInterface > BuildILI(
            const llvm::TargetSubtargetInfo &, const llvm::TargetRegisterInfo *);

      public:
        PatchCompiler(
            mlir::MLIRContext &mlir_cont,
            std::string feature_string,
            std::string cpu,
            std::optional< std::string > backend_name,
            llvm::OptimizationLevel opt_level)
            : mlir_cont(mlir_cont)
            , feature_string(std::move(feature_string))
            , cpu(std::move(cpu))
            , backend_name(backend_name)
            , opt_level(opt_level) {}

        void RewriteModuleToLLVM(mlir::Operation *op);

        const llvm::TargetSubtargetInfo &GetSubTargetForRegion(
            irene3::patchir::RegionOp &region, llvm::TargetMachine *tm);

        PatchMetada OptimizeIntoCompileableLLVM(
            llvm::Module *mod,
            ModuleCallingConventions &cconv,
            mlir::ModuleOp mlirmod,
            const llvm::TargetRegisterInfo *reg_info,
            const IreneLoweringInterface &backend);

        std::pair< std::unique_ptr< llvm::Module >, llvm::Function * > CreateLLVMModForRegion(
            irene3::patchir::RegionOp &region);
        PatchMetada Compile(irene3::patchir::RegionOp &, llvm::raw_pwrite_stream &os);
    };
} // namespace irene3