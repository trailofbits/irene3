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
    class SpecVarProvider final : public rellic::VariableProvider {
        struct Impl;
        std::unique_ptr< Impl > impl;

      public:
        SpecVarProvider(
            rellic::DecompilationContext &dec_ctx,
            anvill::Specification &spec,
            TypeDecoder &type_decoder);
        ~SpecVarProvider();

        clang::QualType ArgumentAsLocal(llvm::Argument &arg) override;

        class Factory final : public rellic::VariableProviderFactory {
            anvill::Specification spec;
            TypeDecoder &type_decoder;

          public:
            Factory(anvill::Specification spec, TypeDecoder &type_decoder);

            std::unique_ptr< rellic::VariableProvider > create(
                rellic::DecompilationContext &ctx) override;
        };
    };
} // namespace irene3