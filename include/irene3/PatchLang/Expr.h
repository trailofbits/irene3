#pragma once

#include <irene3/PatchLang/Lexer.h>
#include <memory>
#include <type_traits>
#include <variant>

namespace irene3::patchlang
{
    class IntLitExpr;
    class StrLitExpr;
    class BoolLitExpr;
    class FloatLitExpr;
    class DeclRefExpr;
    class BinaryExpr;
    class UnaryExpr;
    class GetElementPtrExpr;
    class CallExpr;
    class CallIntrinsicExpr;
    class AllocaExpr;
    class LoadExpr;
    class NullExpr;
    class CastExpr;
    class SelectExpr;
    class AddrOf;

    using Expr = std::variant<
        IntLitExpr,
        StrLitExpr,
        BoolLitExpr,
        FloatLitExpr,
        DeclRefExpr,
        BinaryExpr,
        UnaryExpr,
        GetElementPtrExpr,
        CallExpr,
        CallIntrinsicExpr,
        AllocaExpr,
        LoadExpr,
        NullExpr,
        CastExpr,
        SelectExpr,
        AddrOf >;
    using ExprPtr = std::unique_ptr< Expr >;
    template< typename T >
    concept IsExpr = std::is_same_v< std::remove_cv_t< T >, Expr >;
} // namespace irene3::patchlang