#pragma once

#include <anvill/Result.h>
#include <gap/core/generator.hpp>
#include <string>
#include <string_view>

namespace irene3::patchlang
{
    enum class TokenKind
    {
        /// Special value for uninitialized tokens
        None,
        LParen,
        EscapedLParen,
        RParen,
        LBrace,
        RBrace,
        Colon,
        Semicolon,
        Plus,
        Minus,
        Star,
        Slash,
        Percent,
        Pipe,
        Ampersand,
        Caret,
        Bang,
        Equals,
        LAngle,
        RAngle,
        LE,
        GE,
        NE,
        Assign,
        BinIntLit,
        OctIntLit,
        DecIntLit,
        HexIntLit,
        HexFloatLit,
        StrLit,
        Ident,
        EscapedIdent,
    };

    struct Token {
        using enum TokenKind;

        TokenKind kind;
        std::string_view contents;
        int line;
        int col;

        Token(TokenKind kind, std::string_view contents, int line, int col);
        Token();

        // Returns a human-readable representation of the location of this token
        //
        // Locations are 0-based internally, but we want the human-readable location to be 1-based
        inline std::string GetPositionString() const {
            return std::to_string(line + 1) + ":" + std::to_string(col + 1);
        }
    };

    template< typename T >
    using ParseResult = anvill::Result< T, std::string >;

    gap::generator< ParseResult< Token > > Lex(std::string_view source);
} // namespace irene3::patchlang