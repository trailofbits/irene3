/*
 * Copyright (c) 2023-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <anvill/Specification.h>
#include <memory>
#include <rellic/AST/DecompilationContext.h>
#include <rellic/Decompiler.h>

namespace irene3
{
    class TypeDecoder {
        struct Impl;
        std::unique_ptr< Impl > impl;

      public:
        TypeDecoder();
        ~TypeDecoder();

        clang::QualType Decode(
            rellic::DecompilationContext& dec_ctx,
            anvill::Specification& spec,
            anvill::TypeSpec type_spec,
            llvm::Type* ir_type);
    };
} // namespace irene3