#pragma once

#include "Expr.h"
#include "Lexer.h"

#include <anvill/Type.h>
#include <llvm/ADT/APSInt.h>
#include <string>
#include <type_traits>
#include <variant>

namespace irene3::patchlang
{
    class PrimitiveType;
    class StructType;
    class ArrayType;
    class VectorType;

    using Type    = std::variant< PrimitiveType, StructType, ArrayType, VectorType >;
    using TypePtr = std::unique_ptr< Type >;
    template< typename T >
    concept IsType = std::is_same_v< std::remove_cv_t< T >, Type >;
} // namespace irene3::patchlang