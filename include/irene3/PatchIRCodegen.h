/*
 * Copyright (c) 2024-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include "irene3/Util.h"

#include <anvill/Declarations.h>
#include <anvill/Lifters.h>
#include <anvill/Specification.h>
#include <irene3/DecompileSpec.h>
#include <llvm/IR/LLVMContext.h>
#include <mlir/Dialect/LLVMIR/LLVMTypes.h>
#include <mlir/IR/Attributes.h>
#include <mlir/IR/BuiltinAttributes.h>
#include <mlir/IR/MLIRContext.h>
#include <mlir/IR/OwningOpRef.h>
#include <mlir/Target/LLVMIR/TypeFromLLVM.h>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace irene3
{
    class PatchIRCodegen final {
      public:
        PatchIRCodegen(
            mlir::MLIRContext&, std::istream&, std::unordered_set< uint64_t >&& target_funcs = {});

        llvm::LLVMContext& GetLLVMContext();
        anvill::Specification& GetSpecification();
        mlir::OwningOpRef< mlir::ModuleOp > GetMLIRModule();

      private:
        std::vector< mlir::Attribute > BuildSOffsetVector(
            const std::vector< anvill::OffsetDomain > offsets);
        void translateTypes(
            llvm::ArrayRef< llvm::Type* > types, llvm::SmallVectorImpl< mlir::Type >& result);

        mlir::Type translateType(llvm::Type* ty);

        void NameEntity(llvm::Constant*, const anvill::EntityLifter&);
        std::unique_ptr< llvm::Module > LiftSpec();
        anvill::Specification DecodeSpec(std::istream&);
        mlir::StringAttr StringAttr(const std::string&);
        mlir::FlatSymbolRefAttr SymbolRefAttr(const std::string&);
        mlir::Attribute CreateLowLoc(const anvill::LowLoc&);
        void CreateParam(
            const anvill::BasicBlockVariable&, std::vector< mlir::Value >&, mlir::Block&);

        mlir::Attribute CreatePatchIRValue(const anvill::ValueDecl&);

        void CreateBlockFunc(
            anvill::Uid,
            const anvill::CodeBlock&,
            const anvill::BasicBlockContext&,
            mlir::Block&,
            const std::unordered_map< anvill::Uid, std::string >&);

        llvm::LLVMContext llvm_context;
        std::unordered_map< uint64_t, std::string > symbol_map;
        std::unordered_map< std::string, irene3::GlobalVarInfo > gvars;
        std::unordered_set< uint64_t > target_funcs;

        mlir::MLIRContext& mlir_context;
        anvill::Specification spec;
        std::unique_ptr< llvm::Module > module;

        mlir::OwningOpRef< mlir::ModuleOp > mlir_module;
        mlir::LLVM::LLVMPointerType ptr_type;
        anvill::SpecBlockContexts block_contexts;
        mlir::LLVM::TypeFromLLVMIRTranslator llvm_to_mlir_type;
    };

} // namespace irene3
