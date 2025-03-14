/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
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
    class SpecTypeProvider final : public rellic::TypeProvider {
        struct Impl;
        std::unique_ptr< Impl > impl;

      public:
        SpecTypeProvider(
            rellic::DecompilationContext &dec_ctx,
            anvill::Specification &spec,
            TypeDecoder &type_decoder);
        ~SpecTypeProvider();
        clang::QualType GetGlobalVarType(llvm::GlobalVariable &gvar) override;

        class Factory final : public rellic::TypeProviderFactory {
            anvill::Specification spec;
            TypeDecoder &type_decoder;

          public:
            Factory(anvill::Specification spec, TypeDecoder &type_decoder);

            std::unique_ptr< rellic::TypeProvider > create(
                rellic::DecompilationContext &ctx) override;
        };
    };
} // namespace irene3