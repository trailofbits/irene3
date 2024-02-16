#include <irene3/PatchLang/Lexer.h>

namespace irene3::patchlang
{
    Token::Token(TokenKind kind, std::string_view contents, int line, int col)
        : kind(kind)
        , contents(contents)
        , line(line)
        , col(col) {}
    Token::Token()
        : kind(TokenKind::None) {}

    gap::generator< ParseResult< Token > > Lex(std::string_view source) {
        auto YYCURSOR = source.begin();
        auto YYLIMIT  = source.end();
        const char *YYMARKER;
        int line               = 0;
        const char *line_start = YYCURSOR;

        while (true) {
            const char *tok_start = YYCURSOR;
            auto col              = static_cast< int >(tok_start - line_start);
#define EMIT_TOKEN(kind)                                                  \
    co_yield {                                                            \
        Token{kind, std::string_view{ tok_start, YYCURSOR }, line, col} \
    };                                                                    \
    continue;

            // clang-format off
            /*!re2c
                re2c:define:YYCTYPE = char;
                re2c:yyfill:enable = 0;
                re2c:eof = 0;

                bin_lit = [+-]? "0b" [01]+;
                oct_lit = [+-]? "0" [0-7]+;
                dec_lit = [+-]? ("0" | [1-9] [0-9]*);
                hex_lit = [+-]? "0x" [0-9a-fA-F]+;
                str_chr = [^\\"\n]
                        | "\\\\"
                        | "\\\""
                        | "\\a"
                        | "\\b"
                        | "\\n"
                        | "\\r"
                        | "\\t"
                        | ("\\x" [0-7]{1,3})
                        | ("\\" [0-9a-fA-F]+);
                str_lit = "\"" str_chr* "\"";

                ident = [a-zA-Z_][a-zA-Z0-9_]*;
                escaped_ident = "'" ident;

                ws = [ \t\r]+;

                int_size = [1-9] [0-9]*;
                float_kind = "f16"
                           | "bf16"
                           | "f32"
                           | "f64"
                           | "f80"
                           | "f128"
                           | "f8e5m2"
                           | "f8e5m2fnuz"
                           | "f8e4m3fn"
                           | "f8e4m3fnuz"
                           | "f8e4m3b11fnuz"
                           | "tf32";

                bin_lit ":" int_size   { EMIT_TOKEN(Token::BinIntLit) }
                oct_lit ":" int_size   { EMIT_TOKEN(Token::OctIntLit) }
                dec_lit ":" int_size   { EMIT_TOKEN(Token::DecIntLit) }
                hex_lit ":" int_size   { EMIT_TOKEN(Token::HexIntLit) }
                hex_lit ":" float_kind { EMIT_TOKEN(Token::HexFloatLit) }
                str_lit { EMIT_TOKEN(Token::StrLit) }
                "("     { EMIT_TOKEN(Token::LParen) }
                "'("    { EMIT_TOKEN(Token::EscapedLParen) }
                ")"     { EMIT_TOKEN(Token::RParen) }
                "{"     { EMIT_TOKEN(Token::LBrace) }
                "}"     { EMIT_TOKEN(Token::RBrace) }
                ":"     { EMIT_TOKEN(Token::Colon) }
                ";"     { EMIT_TOKEN(Token::Semicolon) }
                "+"     { EMIT_TOKEN(Token::Plus) }
                "-"     { EMIT_TOKEN(Token::Minus) }
                "*"     { EMIT_TOKEN(Token::Star) }
                "/"     { EMIT_TOKEN(Token::Slash) }
                "%"     { EMIT_TOKEN(Token::Percent) }
                "|"     { EMIT_TOKEN(Token::Pipe) }
                "&"     { EMIT_TOKEN(Token::Ampersand) }
                "^"     { EMIT_TOKEN(Token::Caret) }
                "!"     { EMIT_TOKEN(Token::Bang) }
                "=="    { EMIT_TOKEN(Token::Equals) }
                "<"     { EMIT_TOKEN(Token::LAngle) }
                ">"     { EMIT_TOKEN(Token::RAngle) }
                "<="    { EMIT_TOKEN(Token::LE) }
                ">="    { EMIT_TOKEN(Token::GE) }
                "!="    { EMIT_TOKEN(Token::NE) }
                "="     { EMIT_TOKEN(Token::Assign) }
                ident   { EMIT_TOKEN(Token::Ident) }

                escaped_ident { EMIT_TOKEN(Token::EscapedIdent) }


                * {
                    co_yield {
                        std::to_string(line + 1) + ":" + std::to_string(col + 1) + ": Unrecognized token"
                    };
                }
                $    { co_return; }
                ws   { continue; }
                "\n" { ++line; line_start = YYCURSOR; continue; }
            */
            // clang-format on
        } // namespace irene3::patchlang
    }
} // namespace irene3::patchlang