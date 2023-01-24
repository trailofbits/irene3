/*
 * Copyright (c) 2023-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <anvill/Specification.h>
#include <irene3/TypeDecoder.h>
#include <rellic/Decompiler.h>

namespace irene3
{
    class SpecVarProvider final : public rellic::FunctionLayoutOverride {
        struct Impl;
        std::unique_ptr< Impl > impl;

      public:
        SpecVarProvider(
            rellic::DecompilationContext &dec_ctx,
            anvill::Specification &spec,
            TypeDecoder &type_decoder);
        ~SpecVarProvider();

        bool HasOverride(llvm::Function& func) final;

        std::vector< clang::QualType > GetArguments(llvm::Function& func) final;
        void BeginFunctionVisit(llvm::Function& func, clang::FunctionDecl* fdecl) final;
        bool VisitInstruction(
            llvm::Instruction& insn, clang::FunctionDecl* fdecl, clang::ValueDecl*& vdecl) final;

        class Factory final : public rellic::FunctionLayoutOverrideFactory {
            anvill::Specification spec;
            TypeDecoder& type_decoder;

          public:
            Factory(anvill::Specification spec, TypeDecoder& type_decoder);

            std::unique_ptr< rellic::FunctionLayoutOverride > create(
                rellic::DecompilationContext& ctx) override;
        };
    };
} // namespace irene3