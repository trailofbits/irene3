#pragma once

#include "Exprs.h"
#include "Type.h"

namespace irene3::patchlang
{
    template< typename TType, typename... Ts >
    TypePtr MakeType(Ts&&... ts) {
        return std::make_unique< Type >(TType(std::forward< Ts >(ts)...));
    }

    class PrimitiveType {
        std::string name;
        Token token;

      public:
        PrimitiveType(std::string name, Token tok)
            : name(name)
            , token(tok) {}

        std::string GetName() const { return name; }
        Token GetNameToken() const { return token; }

        Token GetFirstToken() const { return token; }
        Token GetLastToken() const { return token; }

        static TypePtr IntType(size_t width);
        static TypePtr FloatType(size_t width);
    };

    class StructType {
        std::vector< std::unique_ptr< Type > > elems;
        Token first_tok;
        Token last_tok;

      public:
        StructType(std::vector< std::unique_ptr< Type > >&& elems, Token first_tok, Token last_tok)
            : elems(std::move(elems))
            , first_tok(first_tok)
            , last_tok(last_tok) {}

        const std::vector< std::unique_ptr< Type > >& GetElements() const { return elems; }

        Token GetFirstToken() const { return first_tok; }
        Token GetLastToken() const { return last_tok; }
    };

    class ArrayType {
        IntLitExpr size;
        std::unique_ptr< Type > elem_type;
        Token first_tok;
        Token last_tok;

      public:
        ArrayType(
            IntLitExpr&& size, std::unique_ptr< Type > elem_type, Token first_tok, Token last_tok)
            : size(std::move(size))
            , elem_type(std::move(elem_type))
            , first_tok(first_tok)
            , last_tok(last_tok) {}

        const IntLitExpr& GetSize() const { return size; }
        const Type& GetType() const;

        Token GetFirstToken() const { return first_tok; }
        Token GetLastToken() const { return last_tok; }
    };

    class VectorType {
        IntLitExpr size;
        std::unique_ptr< Type > elem_type;
        Token first_tok;
        Token last_tok;

      public:
        VectorType(
            IntLitExpr&& size, std::unique_ptr< Type > elem_type, Token first_tok, Token last_tok)
            : size(std::move(size))
            , elem_type(std::move(elem_type))
            , first_tok(first_tok)
            , last_tok(last_tok) {}

        const IntLitExpr& GetSize() const { return size; }
        const Type& GetType() const { return *elem_type; }

        Token GetFirstToken() const { return first_tok; }
        Token GetLastToken() const { return last_tok; }
    };
} // namespace irene3::patchlang