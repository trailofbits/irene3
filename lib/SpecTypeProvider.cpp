/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "SpecTypeProvider.h"

#include <anvill/Declarations.h>
#include <anvill/Specification.h>
#include <anvill/Type.h>
#include <anvill/Utils.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Type.h>
#include <cstddef>
#include <cstdint>
#include <glog/logging.h>
#include <irene3/Util.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/GlobalValue.h>
#include <memory>
#include <rellic/AST/DecompilationContext.h>
#include <rellic/AST/TypeProvider.h>
#include <unordered_map>
#include <variant>

using namespace rellic;

namespace irene3
{
    struct SpecTypeProvider::Impl {
        DecompilationContext& ctx;
        anvill::Specification spec;
        TypeDecoder& type_decoder;

        Impl(DecompilationContext& ctx, anvill::Specification& spec, TypeDecoder& type_decoder)
            : ctx(ctx)
            , spec(spec)
            , type_decoder(type_decoder) {}

        clang::QualType GetGlobalVarType(llvm::GlobalVariable& gvar) {
            auto pc = GetPCMetadata(&gvar);
            if (!pc.has_value()) {
                return {};
            }

            auto var_spec = spec.VariableAt(*pc);
            if (!var_spec) {
                return {};
            }

            return type_decoder.Decode(ctx, spec, var_spec->spec_type, gvar.getValueType());
        }
    };

    SpecTypeProvider::SpecTypeProvider(
        DecompilationContext& dec_ctx, anvill::Specification& spec, TypeDecoder& type_decoder)
        : TypeProvider(dec_ctx)
        , impl(std::make_unique< Impl >(dec_ctx, spec, type_decoder)) {}
    SpecTypeProvider::~SpecTypeProvider() = default;

    clang::QualType SpecTypeProvider::GetGlobalVarType(llvm::GlobalVariable& gvar) {
        return impl->GetGlobalVarType(gvar);
    }

    SpecTypeProvider::Factory::Factory(anvill::Specification spec, TypeDecoder& type_decoder)
        : spec(spec)
        , type_decoder(type_decoder) {}

    std::unique_ptr< TypeProvider > SpecTypeProvider::Factory::create(
        DecompilationContext& dec_ctx) {
        return std::make_unique< SpecTypeProvider >(dec_ctx, spec, type_decoder);
    }

} // namespace irene3