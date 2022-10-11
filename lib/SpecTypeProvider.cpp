/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "SpecTypeProvider.h"

#include "anvill/Declarations.h"
#include "anvill/Specification.h"
#include "anvill/Type.h"
#include "rellic/AST/DecompilationContext.h"
#include "rellic/AST/TypeProvider.h"

#include <clang/AST/Decl.h>
#include <clang/AST/Type.h>
#include <cstddef>
#include <cstdint>
#include <glog/logging.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/GlobalValue.h>
#include <memory>
#include <sstream>
#include <unordered_map>
#include <variant>

using namespace rellic;

namespace std
{
    template<>
    struct hash< anvill::UnknownType > {
        size_t operator()(const anvill::UnknownType& unk) const {
            return std::hash< unsigned >()(unk.size);
        }
    };
} // namespace std

namespace anvill
{
    bool operator==(const anvill::UnknownType& a, const anvill::UnknownType& b) {
        return a.size == b.size;
    }
} // namespace anvill

namespace irene3
{
    struct SpecTypeProvider::Impl {
        DecompilationContext& ctx;
        anvill::Specification spec;

        std::unordered_map< anvill::TypeSpec, clang::QualType > types;

        using LocalTypeMap = std::unordered_map< int, clang::QualType >;

        Impl(DecompilationContext& ctx, anvill::Specification& spec)
            : ctx(ctx)
            , spec(spec) {
            types = {
  // clang-format off
                    {anvill::BaseType::Bool, ctx.ast_ctx.BoolTy},
                    {anvill::BaseType::Char, ctx.ast_ctx.CharTy},
                    {anvill::BaseType::SignedChar, ctx.ast_ctx.SignedCharTy},
                    {anvill::BaseType::UnsignedChar, ctx.ast_ctx.UnsignedCharTy},
                    {anvill::BaseType::Float128, ctx.ast_ctx.Float128Ty},
                    {anvill::BaseType::Float16, ctx.ast_ctx.Float16Ty},
                    {anvill::BaseType::Float32, ctx.ast_ctx.FloatTy},
                    {anvill::BaseType::Float64, ctx.ast_ctx.DoubleTy},
                    {anvill::BaseType::MMX64, ctx.ast_ctx.DoubleTy},
                    {anvill::BaseType::Float80, ctx.ast_ctx.LongDoubleTy},
                    {anvill::BaseType::Float96, ctx.ast_ctx.LongDoubleTy},
                    {anvill::BaseType::Int128, ctx.ast_ctx.getIntTypeForBitwidth(128, true)},
                    {anvill::BaseType::UInt128, ctx.ast_ctx.getIntTypeForBitwidth(128, false)},
                    {anvill::BaseType::Int16, ctx.ast_ctx.getIntTypeForBitwidth(16, true)},
                    {anvill::BaseType::UInt16, ctx.ast_ctx.getIntTypeForBitwidth(16, false)},
                    {anvill::BaseType::Int24, ctx.ast_ctx.getIntTypeForBitwidth(24, true)},
                    {anvill::BaseType::UInt24, ctx.ast_ctx.getIntTypeForBitwidth(24, false)},
                    {anvill::BaseType::Int32, ctx.ast_ctx.getIntTypeForBitwidth(32, true)},
                    {anvill::BaseType::UInt32, ctx.ast_ctx.getIntTypeForBitwidth(32, false)},
                    {anvill::BaseType::Int64, ctx.ast_ctx.getIntTypeForBitwidth(64, true)},
                    {anvill::BaseType::UInt64, ctx.ast_ctx.getIntTypeForBitwidth(64, false)},
                    {anvill::BaseType::Int8, ctx.ast_ctx.getIntTypeForBitwidth(8, true)},
                    {anvill::BaseType::UInt8, ctx.ast_ctx.getIntTypeForBitwidth(8, false)},
                    {anvill::BaseType::Padding, ctx.ast_ctx.CharTy},
                    {anvill::BaseType::Void, ctx.ast_ctx.VoidTy},
  // clang-format on
            };
        }

        clang::QualType DecodeType(anvill::TypeSpec spec, llvm::Type* ir_type) {
            auto& type = types[spec];
            if (!type.isNull()) {
                return type;
            }

            if (std::holds_alternative< std::shared_ptr< anvill::PointerType > >(spec)) {
                auto ptr = std::get< std::shared_ptr< anvill::PointerType > >(spec);
                if (std::holds_alternative< anvill::UnknownType >(ptr->pointee)) {
                    type = ctx.ast_ctx.VoidPtrTy;
                } else {
                    auto ptr_pointee  = ptr->pointee;
                    auto spec_pointee = this->spec.TypeTranslator().DecodeFromSpec(ptr_pointee);
                    // NOTE(frabert): Consider this just as a sanity check, it should really _never
                    // ever_ fail at this point in the process.
                    CHECK(spec_pointee.Succeeded());
                    auto pointee = DecodeType(ptr_pointee, spec_pointee.Value());
                    type         = ctx.ast_ctx.getPointerType(pointee);
                }
            } else if (std::holds_alternative< std::shared_ptr< anvill::VectorType > >(spec)) {
                auto vec = std::get< std::shared_ptr< anvill::VectorType > >(spec);
                type     = ctx.ast_ctx.getVectorType(
                        DecodeType(
                            vec->base, llvm::cast< llvm::VectorType >(ir_type)->getElementType()),
                        vec->size, clang::VectorType::VectorKind::GenericVector);
            } else if (std::holds_alternative< std::shared_ptr< anvill::ArrayType > >(spec)) {
                CHECK(type.isNull());
                return type;
            } else if (std::holds_alternative< std::shared_ptr< anvill::StructType > >(spec)) {
                auto& tdecl = ctx.type_decls[ir_type];
                if (tdecl) {
                    type = ctx.ast_ctx.getRecordType(clang::cast< clang::RecordDecl >(tdecl));
                } else {
                    auto strct    = std::get< std::shared_ptr< anvill::StructType > >(spec);
                    auto tudecl   = ctx.ast_ctx.getTranslationUnitDecl();
                    auto name     = "struct" + std::to_string(ctx.num_declared_structs++);
                    auto sdecl    = ctx.ast.CreateStructDecl(tudecl, name);
                    tdecl         = sdecl;
                    unsigned i    = 0;
                    auto strct_ty = llvm::cast< llvm::StructType >(ir_type);
                    for (auto member : strct->members) {
                        auto member_type = DecodeType(member, strct_ty->getElementType(i));
                        sdecl->addDecl(ctx.ast.CreateFieldDecl(
                            sdecl, member_type, "field" + std::to_string(i++)));
                    }
                    sdecl->completeDefinition();
                    tudecl->addDecl(sdecl);
                    type = ctx.ast_ctx.getRecordType(sdecl);
                }
            } else if (std::holds_alternative< std::shared_ptr< anvill::FunctionType > >(spec)) {
                auto func    = std::get< std::shared_ptr< anvill::FunctionType > >(spec);
                auto func_ty = llvm::cast< llvm::FunctionType >(ir_type);
                auto ret     = DecodeType(func->return_type, func_ty->getReturnType());
                std::vector< clang::QualType > params;
                unsigned i = 0;
                for (auto param : func->arguments) {
                    params.push_back(DecodeType(param, func_ty->getParamType(i++)));
                }
                clang::FunctionProtoType::ExtProtoInfo epi;
                epi.Variadic = func->is_variadic;
                type         = ctx.ast_ctx.getFunctionType(ret, params, epi);
            } else if (std::holds_alternative< anvill::UnknownType >(spec)) {
                auto unk = std::get< anvill::UnknownType >(spec);
                if (unk.size != UINT32_MAX) {
                    type = ctx.ast_ctx.getIntTypeForBitwidth(unk.size * 8, false);
                }
            }
            return type;
        }

        template< typename T >
        llvm::Optional< size_t > GetPC(T& gval) {
            auto pc_md = gval.getMetadata("pc");
            if (!pc_md) {
                return {};
            }

            auto& pc_opnd    = pc_md->getOperand(0);
            auto pc_constant = llvm::cast< llvm::ConstantAsMetadata >(pc_opnd)->getValue();
            auto pc          = llvm::cast< llvm::ConstantInt >(pc_constant);
            return pc->getZExtValue();
        }

        clang::QualType GetArgumentType(llvm::Argument& arg) {
            auto pc = GetPC(*arg.getParent());
            if (!pc.hasValue()) {
                return {};
            }

            auto func_spec = spec.FunctionAt(*pc);
            if (!func_spec) {
                return {};
            }

            auto param_spec = func_spec->params[arg.getArgNo()];

            return DecodeType(param_spec.spec_type, arg.getType());
        }

        clang::QualType GetFunctionReturnType(llvm::Function& func) {
            auto pc = GetPC(func);
            if (!pc.hasValue()) {
                return {};
            }

            auto func_spec = spec.FunctionAt(*pc);
            if (!func_spec) {
                return {};
            }

            auto& ret_types = func_spec->returns;
            if (ret_types.size() == 0) {
                return {};
            }

            if (ret_types.size() == 1) {
                return DecodeType(ret_types[0].spec_type, func.getReturnType());
            }

            auto type   = llvm::cast< llvm::StructType >(func.getReturnType());
            auto& tdecl = ctx.type_decls[type];
            if (tdecl) {
                return ctx.ast_ctx.getRecordType(clang::cast< clang::RecordDecl >(tdecl));
            }

            std::vector< clang::QualType > elems;
            auto tudecl{ ctx.ast_ctx.getTranslationUnitDecl() };
            auto strct{ llvm::cast< llvm::StructType >(type) };
            auto sname{ strct->isLiteral()
                            ? ("literal_struct_" + std::to_string(ctx.num_literal_structs++))
                            : strct->getName().str() };
            if (sname.empty()) {
                sname = "struct" + std::to_string(ctx.num_declared_structs++);
            }

            clang::RecordDecl* sdecl;
            // Create a C struct declaration
            tdecl = sdecl = ctx.ast.CreateStructDecl(tudecl, sname);

            // Add fields to the C struct
            for (unsigned i = 0; i < type->getNumElements(); ++i) {
                auto elem  = type->getElementType(i);
                auto etype = DecodeType(func_spec->returns[i].spec_type, elem);
                auto fname = "field" + std::to_string(i);
                sdecl->addDecl(ctx.ast.CreateFieldDecl(sdecl, etype, fname));
            }

            // Complete the C struct definition
            sdecl->completeDefinition();
            // Add C struct to translation unit
            tudecl->addDecl(sdecl);

            return ctx.ast_ctx.getRecordType(clang::cast< clang::RecordDecl >(tdecl));
        }

        clang::QualType GetGlobalVarType(llvm::GlobalVariable& gvar) {
            auto pc = GetPC(gvar);
            if (!pc.hasValue()) {
                return {};
            }

            auto var_spec = spec.VariableAt(*pc);
            if (!var_spec) {
                return {};
            }

            return DecodeType(var_spec->spec_type, gvar.getValueType());
        }
    };

    SpecTypeProvider::SpecTypeProvider(DecompilationContext& dec_ctx, anvill::Specification& spec)
        : TypeProvider(dec_ctx)
        , impl(std::make_unique< Impl >(dec_ctx, spec)) {}
    SpecTypeProvider::~SpecTypeProvider() = default;

    clang::QualType SpecTypeProvider::GetArgumentType(llvm::Argument& arg) {
        return impl->GetArgumentType(arg);
    }

    clang::QualType SpecTypeProvider::GetFunctionReturnType(llvm::Function& func) {
        return impl->GetFunctionReturnType(func);
    }

    clang::QualType SpecTypeProvider::GetGlobalVarType(llvm::GlobalVariable& gvar) {
        return impl->GetGlobalVarType(gvar);
    }

    SpecTypeProvider::Factory::Factory(anvill::Specification spec)
        : spec(spec) {}

    std::unique_ptr< TypeProvider > SpecTypeProvider::Factory::create(
        DecompilationContext& dec_ctx) {
        return std::make_unique< SpecTypeProvider >(dec_ctx, spec);
    }

} // namespace irene3