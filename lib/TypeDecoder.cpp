/*
 * Copyright (c) 2023-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Specification.h>
#include <anvill/Type.h>
#include <clang/AST/PrettyPrinter.h>
#include <clang/AST/Type.h>
#include <irene3/TypeDecoder.h>
#include <rellic/AST/DecompilationContext.h>
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

namespace std
{
    std::string to_string(clang::QualType qt) {
        std::string s;
        llvm::raw_string_ostream os(s);
        qt.print(os, { {} });
        return s;
    }
} // namespace std

namespace irene3
{
    struct TypeDecoder::Impl {
        std::unordered_map< anvill::TypeSpec, clang::QualType > types;
    };

    TypeDecoder::TypeDecoder()
        : impl(std::make_unique< Impl >()) {}
    TypeDecoder::~TypeDecoder() = default;

    clang::QualType TypeDecoder::Decode(
        DecompilationContext& ctx,
        anvill::Specification& spec,
        anvill::TypeSpec type_spec,
        llvm::Type* ir_type) {
        auto& type = impl->types[type_spec];
        if (!type.isNull()) {
            return type;
        }

        if (std::holds_alternative< anvill::BaseType >(type_spec)) {
            auto bt = std::get< anvill::BaseType >(type_spec);
            switch (bt) {
                case anvill::BaseType::Bool: type = ctx.ast_ctx.BoolTy; break;
                case anvill::BaseType::Char: type = ctx.ast_ctx.CharTy; break;
                case anvill::BaseType::SignedChar: type = ctx.ast_ctx.SignedCharTy; break;
                case anvill::BaseType::UnsignedChar: type = ctx.ast_ctx.UnsignedCharTy; break;
                case anvill::BaseType::Float128: type = ctx.ast_ctx.Float128Ty; break;
                case anvill::BaseType::Float16: type = ctx.ast_ctx.Float16Ty; break;
                case anvill::BaseType::Float32: type = ctx.ast_ctx.FloatTy; break;
                case anvill::BaseType::Float64: type = ctx.ast_ctx.DoubleTy; break;
                case anvill::BaseType::MMX64: type = ctx.ast_ctx.DoubleTy; break;
                case anvill::BaseType::Float80: type = ctx.ast_ctx.LongDoubleTy; break;
                case anvill::BaseType::Float96: type = ctx.ast_ctx.LongDoubleTy; break;
                case anvill::BaseType::Int128:
                    type = ctx.ast_ctx.getIntTypeForBitwidth(128, true);
                    break;
                case anvill::BaseType::UInt128:
                    type = ctx.ast_ctx.getIntTypeForBitwidth(128, false);
                    break;
                case anvill::BaseType::Int16:
                    type = ctx.ast_ctx.getIntTypeForBitwidth(16, true);
                    break;
                case anvill::BaseType::UInt16:
                    type = ctx.ast_ctx.getIntTypeForBitwidth(16, false);
                    break;
                case anvill::BaseType::Int24:
                    type = ctx.ast_ctx.getIntTypeForBitwidth(24, true);
                    break;
                case anvill::BaseType::UInt24:
                    type = ctx.ast_ctx.getIntTypeForBitwidth(24, false);
                    break;
                case anvill::BaseType::Int32:
                    type = ctx.ast_ctx.getIntTypeForBitwidth(32, true);
                    break;
                case anvill::BaseType::UInt32:
                    type = ctx.ast_ctx.getIntTypeForBitwidth(32, false);
                    break;
                case anvill::BaseType::Int64:
                    type = ctx.ast_ctx.getIntTypeForBitwidth(64, true);
                    break;
                case anvill::BaseType::UInt64:
                    type = ctx.ast_ctx.getIntTypeForBitwidth(64, false);
                    break;
                case anvill::BaseType::Int8:
                    type = ctx.ast_ctx.getIntTypeForBitwidth(8, true);
                    break;
                case anvill::BaseType::UInt8:
                    type = ctx.ast_ctx.getIntTypeForBitwidth(8, false);
                    break;
                case anvill::BaseType::Padding: type = ctx.ast_ctx.CharTy; break;
                case anvill::BaseType::Void: type = ctx.ast_ctx.VoidTy; break;
            }
        } else if (std::holds_alternative< std::shared_ptr< anvill::PointerType > >(type_spec)) {
            auto ptr = std::get< std::shared_ptr< anvill::PointerType > >(type_spec);
            if (std::holds_alternative< anvill::UnknownType >(ptr->pointee)) {
                type = ctx.ast_ctx.VoidPtrTy;
            } else {
                auto ptr_pointee  = ptr->pointee;
                auto spec_pointee = spec.TypeTranslator().DecodeFromSpec(ptr_pointee);
                // NOTE(frabert): Consider this just as a sanity check, it should really _never
                // ever_ fail at this point in the process.
                CHECK(spec_pointee.Succeeded());
                auto pointee = Decode(ctx, spec, ptr_pointee, spec_pointee.Value());
                type         = ctx.ast_ctx.getPointerType(pointee);
            }
        } else if (std::holds_alternative< std::shared_ptr< anvill::VectorType > >(type_spec)) {
            auto vec = std::get< std::shared_ptr< anvill::VectorType > >(type_spec);
            type     = ctx.ast_ctx.getVectorType(
                    Decode(
                        ctx, spec, vec->base,
                        llvm::cast< llvm::VectorType >(ir_type)->getElementType()),
                    vec->size, clang::VectorType::VectorKind::GenericVector);
        } else if (std::holds_alternative< std::shared_ptr< anvill::ArrayType > >(type_spec)) {
            CHECK(type.isNull());
            return type;
        } else if (std::holds_alternative< std::shared_ptr< anvill::StructType > >(type_spec)) {
            auto& tdecl = ctx.type_decls[ir_type];
            if (tdecl) {
                type = ctx.ast_ctx.getRecordType(clang::cast< clang::RecordDecl >(tdecl));
            } else {
                auto strct    = std::get< std::shared_ptr< anvill::StructType > >(type_spec);
                auto tudecl   = ctx.ast_ctx.getTranslationUnitDecl();
                auto name     = "struct" + std::to_string(ctx.num_declared_structs++);
                auto sdecl    = ctx.ast.CreateStructDecl(tudecl, name);
                tdecl         = sdecl;
                unsigned i    = 0;
                auto strct_ty = llvm::cast< llvm::StructType >(ir_type);
                for (auto member : strct->members) {
                    auto elem_ty     = strct_ty->getElementType(i);
                    auto member_type = Decode(ctx, spec, member, elem_ty);
                    if (member_type.isNull()) {
                        member_type = ctx.GetQualType(elem_ty);
                    }
                    sdecl->addDecl(
                        ctx.ast.CreateFieldDecl(sdecl, member_type, "field" + std::to_string(i++)));
                }
                sdecl->completeDefinition();
                tudecl->addDecl(sdecl);
                type = ctx.ast_ctx.getRecordType(sdecl);
            }
        } else if (std::holds_alternative< std::shared_ptr< anvill::FunctionType > >(type_spec)) {
            auto func    = std::get< std::shared_ptr< anvill::FunctionType > >(type_spec);
            auto func_ty = llvm::cast< llvm::FunctionType >(ir_type);
            auto ret     = Decode(ctx, spec, func->return_type, func_ty->getReturnType());
            std::vector< clang::QualType > params;
            unsigned i = 0;
            for (auto param : func->arguments) {
                params.push_back(Decode(ctx, spec, param, func_ty->getParamType(i++)));
            }
            clang::FunctionProtoType::ExtProtoInfo epi;
            epi.Variadic = func->is_variadic;
            type         = ctx.ast_ctx.getFunctionType(ret, params, epi);
        } else if (std::holds_alternative< anvill::UnknownType >(type_spec)) {
            auto unk = std::get< anvill::UnknownType >(type_spec);
            if (unk.size != UINT32_MAX) {
                type = ctx.ast_ctx.getIntTypeForBitwidth(unk.size * 8, false);
            }
        }
        return type;
    }
} // namespace irene3