/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <rellic/Decompiler.h>
#include <anvill/Specification.h>

namespace irene3
{
    class SpecTypeProvider final : public rellic::TypeProvider {
        struct Impl;
        std::unique_ptr< Impl > impl;

      public:
        SpecTypeProvider(rellic::DecompilationContext &dec_ctx, anvill::Specification &spec);
        ~SpecTypeProvider();
        clang::QualType GetArgumentType(llvm::Argument &arg) override;
        clang::QualType GetFunctionReturnType(llvm::Function &func) override;
        clang::QualType GetGlobalVarType(llvm::GlobalVariable &gvar) override;

        class Factory final : public rellic::TypeProviderFactory {
            anvill::Specification spec;

          public:
            Factory(anvill::Specification spec);

            std::unique_ptr< rellic::TypeProvider > create(
                rellic::DecompilationContext &ctx) override;
        };
    };
} // namespace irene3