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
#include <unordered_set>

namespace irene3
{
    class SpecLayoutOverride final : public rellic::FunctionLayoutOverride {
        struct Impl;
        std::unique_ptr< Impl > impl;

      public:
        SpecLayoutOverride(
            rellic::DecompilationContext& dec_ctx,
            anvill::Specification& spec,
            TypeDecoder& type_decoder,
            bool stack_grows_down,
            bool should_preserve_unused_decls,
            const std::unordered_set< std::string >& required_globals);
        ~SpecLayoutOverride();

        bool HasOverride(llvm::Function& func) final;

        std::vector< clang::QualType > GetArguments(llvm::Function& func) final;

        void BeginFunctionVisit(llvm::Function& func, clang::FunctionDecl* fdecl) final;
        bool VisitInstruction(
            llvm::Instruction& insn, clang::FunctionDecl* fdecl, clang::ValueDecl*& vdecl) final;
        bool NeedsDereference(llvm::Function& func, llvm::Value& val) final;

        class Factory final : public rellic::FunctionLayoutOverrideFactory {
            anvill::Specification spec;
            TypeDecoder& type_decoder;
            bool stack_grows_down;
            std::unordered_set< std::string > required_globals;

          public:
            Factory(
                anvill::Specification spec,
                TypeDecoder& type_decoder,
                bool stack_grows_down,
                const std::unordered_set< std::string >& required_globals);

            std::unique_ptr< rellic::FunctionLayoutOverride > create(
                rellic::DecompilationContext& ctx) override;
        };
    };

    class UnsafeSpecLayoutOverride final : public rellic::FunctionLayoutOverride {
        struct Impl;
        std::unique_ptr< Impl > impl;

      public:
        UnsafeSpecLayoutOverride(
            rellic::DecompilationContext& dec_ctx,
            anvill::Specification& spec,
            TypeDecoder& type_decoder,
            bool should_preserve_unused_decls,
            const std::unordered_set< std::string >& required_globals);
        ~UnsafeSpecLayoutOverride();

        bool HasOverride(llvm::Function& func) final;

        std::vector< clang::QualType > GetArguments(llvm::Function& func) final;
        void BeginFunctionVisit(llvm::Function& func, clang::FunctionDecl* fdecl) final;
        bool VisitInstruction(
            llvm::Instruction& insn, clang::FunctionDecl* fdecl, clang::ValueDecl*& vdecl) final;
        bool NeedsDereference(llvm::Function& func, llvm::Value& val) final;

        class Factory final : public rellic::FunctionLayoutOverrideFactory {
            anvill::Specification spec;
            TypeDecoder& type_decoder;
            std::unordered_set< std::string > required_globals;

          public:
            Factory(
                anvill::Specification spec,
                TypeDecoder& type_decoder,
                const std::unordered_set< std::string >& required_globals);

            std::unique_ptr< rellic::FunctionLayoutOverride > create(
                rellic::DecompilationContext& ctx) override;
        };
    };
} // namespace irene3