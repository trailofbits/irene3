/*
 * Copyright (c) 2023-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "SpecVarProvider.h"

#include <anvill/Specification.h>
#include <clang/AST/Type.h>
#include <irene3/Util.h>
#include <rellic/AST/DecompilationContext.h>
#include <rellic/AST/VariableProvider.h>
#include <string>

namespace irene3
{
    using namespace rellic;
    struct SpecVarProvider::Impl {
        DecompilationContext& ctx;
        anvill::Specification spec;
        TypeDecoder& type_decoder;

        Impl(DecompilationContext& ctx, anvill::Specification& spec, TypeDecoder& type_decoder)
            : ctx(ctx)
            , spec(spec)
            , type_decoder(type_decoder) {}

        clang::QualType ArgumentAsLocal(llvm::Argument& arg) {
            auto func       = arg.getParent();
            auto block_addr = anvill::GetBasicBlockAddr(func);
            if (!block_addr.has_value()) {
                return {};
            }

            auto block_contexts  = spec.GetBlockContexts();
            auto maybe_block_ctx = block_contexts.GetBasicBlockContextForAddr(*block_addr);
            if (!maybe_block_ctx.has_value()) {
                return {};
            }

            const anvill::BasicBlockContext& block_ctx = maybe_block_ctx.value();
            auto available_vars                        = block_ctx.GetAvailableVariables();
            auto num_available_vars                    = available_vars.size();

            auto first_var_idx = func->arg_size() - num_available_vars;
            if (arg.getArgNo() < first_var_idx) {
                return {};
            }

            auto& param_spec = available_vars[arg.getArgNo() - first_var_idx];

            auto type = type_decoder.Decode(ctx, spec, param_spec.spec_type, arg.getType());
            return type;
        }
    };

    SpecVarProvider::SpecVarProvider(
        DecompilationContext& dec_ctx, anvill::Specification& spec, TypeDecoder& type_decoder)
        : VariableProvider(dec_ctx)
        , impl(std::make_unique< Impl >(dec_ctx, spec, type_decoder)) {}
    SpecVarProvider::~SpecVarProvider() = default;

    clang::QualType SpecVarProvider::ArgumentAsLocal(llvm::Argument& arg) {
        return impl->ArgumentAsLocal(arg);
    }

    SpecVarProvider::Factory::Factory(anvill::Specification spec, TypeDecoder& type_decoder)
        : spec(spec)
        , type_decoder(type_decoder) {}

    std::unique_ptr< VariableProvider > SpecVarProvider::Factory::create(
        rellic::DecompilationContext& dec_ctx) {
        return std::make_unique< SpecVarProvider >(dec_ctx, spec, type_decoder);
    }
} // namespace irene3