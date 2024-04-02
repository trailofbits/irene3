#pragma once
#include "Exprs.h"
#include "Lexer.h"
#include "Location.h"
#include "Stmt.h"
#include "Types.h"
#include "irene3/PatchLang/Expr.h"
#include "irene3/PatchLang/Locations.h"

#include <anvill/Result.h>
#include <concepts>
#include <optional>
#include <sstream>
#include <type_traits>
#include <variant>
#include <vector>

namespace irene3::patchlang
{
    enum class AttrKind
    {
        ExternalName,
        Identifier,
        IntLit,
        BoolLit,
        Type,
        StrLit,
        Expr,
        Location,
        ReprRegLocs
    };

    template< typename T >
    concept Attribute = requires() {
        { T::name } -> std::convertible_to< const char* >;
        { T::optional } -> std::convertible_to< bool >;
        { T::kind } -> std::convertible_to< AttrKind >;
    };

    namespace detail
    {
        namespace attrs
        {
            template< AttrKind Kind >
            struct attr_type;

            template<>
            struct attr_type< AttrKind::ExternalName > {
                using type = Token;
            };

            template<>
            struct attr_type< AttrKind::Identifier > {
                using type = Token;
            };

            template<>
            struct attr_type< AttrKind::IntLit > {
                using type = IntLitExpr;
            };

            template<>
            struct attr_type< AttrKind::BoolLit > {
                using type = BoolLitExpr;
            };

            template<>
            struct attr_type< AttrKind::Type > {
                using type = TypePtr;
            };

            template<>
            struct attr_type< AttrKind::StrLit > {
                using type = StrLitExpr;
            };

            template<>
            struct attr_type< AttrKind::Expr > {
                using type = ExprPtr;
            };

            template<>
            struct attr_type< AttrKind::Location > {
                using type = Location;
            };

            template<>
            struct attr_type< AttrKind::ReprRegLocs > {
                using type = std::vector< StackOffset >;
            };

            template< Attribute Attr >
            using attr_type_t = typename attr_type< Attr::kind >::type;

            template< Attribute Attr >
            using attr_return_type_t = std::conditional_t<
                Attr::optional,
                std::optional< attr_type_t< Attr > >,
                attr_type_t< Attr > >;

            template< bool optional, size_t I >
            struct extract_result;

            template< size_t I >
            struct extract_result< true, I > {
                constexpr auto operator()(auto& tuple) const {
                    return std::move(std::get< I >(tuple));
                }
            };

            template< size_t I >
            struct extract_result< false, I > {
                constexpr auto operator()(auto& tuple) const {
                    return std::move(*std::get< I >(tuple));
                }
            };

            template< size_t I, Attribute Attr >
            struct attr_index_pair {
                using attr                    = Attr;
                static constexpr size_t index = I;
            };

            template< typename... Ts >
            struct attr_index_pair_seq {
                static constexpr size_t size = sizeof...(Ts);
            };

            template< size_t I, typename... Ts >
            struct make_attr_seq;

            template< typename... Pairs, size_t I, Attribute Attr, Attribute... Attrs >
            struct make_attr_seq< I, attr_index_pair_seq< Pairs... >, Attr, Attrs... > {
                using type = typename make_attr_seq<
                    I + 1,
                    attr_index_pair_seq< Pairs..., attr_index_pair< I, Attr > >,
                    Attrs... >::type;
            };

            template< size_t I, typename... Pairs >
            struct make_attr_seq< I, attr_index_pair_seq< Pairs... > > {
                using type = attr_index_pair_seq< Pairs... >;
            };

            template< Attribute... Attrs >
            using attr_seq = typename make_attr_seq< 0, attr_index_pair_seq<>, Attrs... >::type;

            template< typename... Pairs >
            std::optional< std::string > check_missing_attrs_impl(
                const auto& tup, attr_index_pair_seq< Pairs... >) {
                if ((!(std::get< Pairs::index >(tup).has_value() || Pairs::attr::optional)
                     || ...)) {
                    std::stringstream err_msg;
                    err_msg << "Missing mandatory attributes";
                    ((!(std::get< Pairs::index >(tup).has_value() || Pairs::attr::optional)
                          ? (err_msg << " `" << Pairs::attr::name << '`')
                          : err_msg),
                     ...);
                    return err_msg.str();
                }
                return std::nullopt;
            }

            template< Attribute... Attrs >
            std::optional< std::string > check_missing_attrs(const auto& tup) {
                return check_missing_attrs_impl(tup, attr_seq< Attrs... >());
            }

            template< typename... Pairs >
            auto extract_results_impl(auto&& t, attr_index_pair_seq< Pairs... >)
                -> std::tuple< attr_return_type_t< typename Pairs::attr >... > {
                return std::make_tuple(
                    std::move(extract_result< Pairs::attr::optional, Pairs::index >{}(t))...);
            }

            template< Attribute... Attrs >
            auto extract_results(auto&& tuple) {
                return extract_results_impl(std::move(tuple), attr_seq< Attrs... >{});
            }
        }; // namespace attrs
    }      // namespace detail

    class Parser {
        gap::generator< ParseResult< Token > > tokens;
        std::optional< Token > lookahead;

        ParseResult< std::optional< Token > > PeekToken();
        ParseResult< std::optional< Token > > GetToken();
        template< TokenKind... Kinds >
        ParseResult< Token > GetToken() {
            auto maybe_tok = GetToken();
            if (!maybe_tok.Succeeded()) {
                return maybe_tok.TakeError();
            }

            auto tok = maybe_tok.TakeValue();

            if (!tok.has_value()) {
                return { "Unexpected EOF" };
            }

            if (((tok->kind != Kinds) && ...)) {
                return { tok->GetPositionString() + ": Invalid token found" };
            }

            return *tok;
        }

        template< TokenKind... Kinds >
        ParseResult< Token > PeekToken() {
            auto maybe_tok = PeekToken();
            if (!maybe_tok.Succeeded()) {
                return maybe_tok.TakeError();
            }

            auto tok = maybe_tok.TakeValue();
            if (!tok.has_value()) {
                return { "Unexpected EOF" };
            }

            if (((tok->kind != Kinds) && ...)) {
                return { tok->GetPositionString() + ": Invalid token found" };
            }

            return *tok;
        }

        ParseResult< Token > GetIdent(const std::vector< std::string_view >& values) {
            auto maybe_tok = GetToken();
            if (!maybe_tok.Succeeded()) {
                return maybe_tok.TakeError();
            }

            auto tok = maybe_tok.TakeValue();
            if (!tok.has_value()) {
                return { "Unexpected EOF" };
            }

            if (tok->kind != Token::Ident) {
                std::stringstream msg;
                msg << tok->GetPositionString() << ": Invalid token found, expected one of";
                for (auto value : values) {
                    msg << " `" << value << "`,";
                }
                msg << " found `" << tok->contents << "` instead";
                return { msg.str() };
            }

            for (const auto& str : values) {
                if (tok->contents == str) {
                    return *tok;
                }
            }

            std::stringstream msg;
            msg << tok->GetPositionString() << ": Invalid identifier found, expected one of";
            for (auto value : values) {
                msg << " `" << value << "`,";
            }
            msg << " found `" << tok->contents << "` instead";
            return { msg.str() };
        }

        ParseResult< std::optional< Token > > MaybeGetIdent(
            const std::vector< std::string_view >& values) {
            auto maybe_tok = PeekToken();
            if (!maybe_tok.Succeeded()) {
                return maybe_tok.TakeError();
            }

            auto tok = maybe_tok.TakeValue();
            if (!tok.has_value()) {
                return { "Unexpected EOF" };
            }

            if (tok->kind != Token::Ident) {
                return { std::nullopt };
            }

            for (const auto& str : values) {
                if (tok->contents == str) {
                    GetToken();
                    return tok;
                }
            }

            return { std::nullopt };
        }

        ParseResult< IntLitExpr > ParseIntLit();
        ParseResult< StrLitExpr > ParseStrLit();
        ParseResult< BoolLitExpr > ParseBexpr();
        ParseResult< FloatLitExpr > ParseFloatLit();
        ParseResult< FloatLitExpr > ParseDecFloatLit();

        template< AttrKind Kind, typename Tup, size_t I >
        struct parse_into_tuple;

        template< typename Tup, size_t I >
        struct parse_into_tuple< AttrKind::ExternalName, Tup, I > {
            static ParseResult< Token > Parse(Parser& parser, Tup& tuple) {
                auto maybe_tok = parser.GetToken();
                if (!maybe_tok.Succeeded()) {
                    return maybe_tok.TakeError();
                }

                auto tok = maybe_tok.TakeValue();
                if (!tok) {
                    return { "Unexpected EOF while parsing an external name" };
                }
                if (tok->kind != Token::Ident && tok->kind != Token::StrLit) {
                    return { tok->GetPositionString()
                             + ": External name must be an identifier or string literal" };
                }

                auto& attr = std::get< I >(tuple);
                if (attr) {
                    return { tok->GetPositionString()
                             + ": Attribute has already been set (previous value at "
                             + attr->GetPositionString() + ")" };
                }

                attr = *tok;
                return *tok;
            }
        };

        // TODO(Ian), this could probably be generic over some repeated attr
        template< typename Tup, size_t I >
        struct parse_into_tuple< AttrKind::ReprRegLocs, Tup, I > {
            static ParseResult< Token > Parse(Parser& parser, Tup& tuple) {
                auto tokres = parser.GetToken< Token::LParen >();
                if (!tokres.Succeeded()) {
                    return tokres.TakeError();
                }

                std::vector< StackOffset > locs;
                while (true) {
                    auto peek = parser.PeekToken();
                    if (!peek.Succeeded()) {
                        return peek.TakeError();
                    }

                    if (!peek->has_value() || peek->value().kind == Token::RParen) {
                        break;
                    }

                    auto soff = parser.ParseStackOffset();
                    if (!soff.Succeeded()) {
                        return soff.TakeError();
                    }

                    locs.push_back(soff.TakeValue());
                }

                auto end = parser.GetToken< Token::RParen >();
                if (!end.Succeeded()) {
                    return end.TakeError();
                }

                auto& attr = std::get< I >(tuple);
                if (attr) {
                    return "Attribute has already been set in repr loc "
                           + tokres->GetPositionString();
                }

                attr = locs;
                return end;
            }
        };

        template< typename Tup, size_t I >
        struct parse_into_tuple< AttrKind::Identifier, Tup, I > {
            static ParseResult< Token > Parse(Parser& parser, Tup& tuple) {
                auto tok = parser.GetToken< Token::Ident >();
                if (!tok.Succeeded()) {
                    return tok.TakeError();
                }

                auto& attr = std::get< I >(tuple);
                if (attr) {
                    return tok->GetPositionString()
                           + ": Attribute has already been set (previous value at "
                           + attr->GetPositionString() + ")";
                }

                attr = tok.TakeValue();
                return *attr;
            }
        };

        template< typename Tup, size_t I >
        struct parse_into_tuple< AttrKind::IntLit, Tup, I > {
            static ParseResult< Token > Parse(Parser& parser, Tup& tuple) {
                auto tok = parser.ParseIntLit();
                if (!tok.Succeeded()) {
                    return tok.TakeError();
                }

                auto& attr = std::get< I >(tuple);
                if (attr) {
                    return tok->GetToken().GetPositionString()
                           + ": Attribute has already been set (previous value at "
                           + attr->GetToken().GetPositionString() + ")";
                }

                attr = tok.TakeValue();
                return attr->GetLastToken();
            }
        };

        template< typename Tup, size_t I >
        struct parse_into_tuple< AttrKind::BoolLit, Tup, I > {
            static ParseResult< Token > Parse(Parser& parser, Tup& tuple) {
                auto tok = parser.ParseBexpr();
                if (!tok.Succeeded()) {
                    return tok.TakeError();
                }

                auto& attr = std::get< I >(tuple);
                if (attr) {
                    return tok->GetToken().GetPositionString()
                           + ": Attribute has already been set (previous value at "
                           + attr->GetToken().GetPositionString() + ")";
                }

                attr = tok.TakeValue();
                return attr->GetLastToken();
            }
        };

        template< typename Tup, size_t I >
        struct parse_into_tuple< AttrKind::StrLit, Tup, I > {
            static ParseResult< Token > Parse(Parser& parser, Tup& tuple) {
                auto tok = parser.ParseStrLit();
                if (!tok.Succeeded()) {
                    return tok.TakeError();
                }

                auto& attr = std::get< I >(tuple);
                if (attr) {
                    return tok->GetToken().GetPositionString()
                           + ": Attribute has already been set (previous value at "
                           + attr->GetToken().GetPositionString() + ")";
                }

                attr = tok.TakeValue();
                return attr->GetLastToken();
            }
        };

        template< typename Tup, size_t I >
        struct parse_into_tuple< AttrKind::Expr, Tup, I > {
            static ParseResult< Token > Parse(Parser& parser, Tup& tuple) {
                auto expr = parser.ParseExpr();
                if (!expr.Succeeded()) {
                    return expr.TakeError();
                }

                auto& attr = std::get< I >(tuple);
                if (attr) {
                    auto expr_first_tok = std::visit(
                        [](const auto& expr) { return expr.GetFirstToken(); }, *expr.Value());
                    auto prev_first_tok
                        = std::visit([](const auto& expr) { return expr.GetFirstToken(); }, **attr);
                    return expr_first_tok.GetPositionString()
                           + ": Attribute has already been set (previous value at "
                           + prev_first_tok.GetPositionString() + ")";
                }

                attr          = std::move(expr.TakeValue());
                auto last_tok = std::visit([](const auto& n) { return n.GetLastToken(); }, **attr);
                return last_tok;
            }
        };

        template< typename Tup, size_t I >
        struct parse_into_tuple< AttrKind::Type, Tup, I > {
            static ParseResult< Token > Parse(Parser& parser, Tup& tuple) {
                auto type = parser.ParseType();
                if (!type.Succeeded()) {
                    return type.TakeError();
                }

                auto& attr = std::get< I >(tuple);
                if (attr.has_value()) {
                    auto type_first_tok = std::visit(
                        [](const auto& n) { return n.GetFirstToken(); }, *type.Value());
                    auto prev_first_tok
                        = std::visit([](const auto& n) { return n.GetFirstToken(); }, **attr);
                    return type_first_tok.GetPositionString()
                           + ": Attribute has already been set (previous value at "
                           + prev_first_tok.GetPositionString() + ")";
                }

                attr          = std::move(type.TakeValue());
                auto last_tok = std::visit([](const auto& n) { return n.GetLastToken(); }, **attr);
                return last_tok;
            }
        };

        template< typename Tup, size_t I >
        struct parse_into_tuple< AttrKind::Location, Tup, I > {
            static ParseResult< Token > Parse(Parser& parser, Tup& tuple) {
                auto loc = parser.ParseLocation();
                if (!loc.Succeeded()) {
                    return loc.TakeError();
                }

                auto& attr = std::get< I >(tuple);
                if (attr.has_value()) {
                    auto loc_first_tok
                        = std::visit([](const auto& n) { return n.GetFirstToken(); }, loc.Value());
                    auto prev_first_tok
                        = std::visit([](const auto& n) { return n.GetFirstToken(); }, *attr);
                    return loc_first_tok.GetPositionString()
                           + ": Attribute has already been set (previous value at "
                           + prev_first_tok.GetPositionString() + ")";
                }

                attr          = std::move(loc.TakeValue());
                auto last_tok = std::visit([](const auto& n) { return n.GetLastToken(); }, *attr);
                return last_tok;
            }
        };

        template< typename Tup, size_t I, Attribute... Attrs >
        struct parse_attr;

        template< typename Tup, size_t I, Attribute Attr, Attribute... Attrs >
        struct parse_attr< Tup, I, Attr, Attrs... > {
            static ParseResult< Token > Parse(Parser& parser, Tup& tuple, Token attr_name) {
                if (attr_name.contents != Attr::name) {
                    return parse_attr< Tup, I + 1, Attrs... >::Parse(parser, tuple, attr_name);
                }
                return parse_into_tuple< Attr::kind, Tup, I >::Parse(parser, tuple);
            }
        };

        template< typename Tup, size_t I, Attribute Attr >
        struct parse_attr< Tup, I, Attr > {
            static ParseResult< Token > Parse(Parser& parser, Tup& tuple, Token attr_name) {
                return parse_into_tuple< Attr::kind, Tup, I >::Parse(parser, tuple);
            }
        };

        template< Attribute... Attrs >
        ParseResult< std::optional< Token > > ParseAttribute(auto& res) {
            auto maybe_name = MaybeGetIdent({
                Attrs::name...,
            });
            if (!maybe_name.Succeeded()) {
                return maybe_name.TakeError();
            }
            if (!maybe_name.Value()) {
                return { std::nullopt };
            }
            auto name = *maybe_name.TakeValue();

            auto colon = GetToken< Token::Colon >();
            if (!colon.Succeeded()) {
                return colon.TakeError();
            }

            auto parse_res = parse_attr< decltype(res), 0, Attrs... >::Parse(*this, res, name);
            if (!parse_res.Succeeded()) {
                return parse_res.TakeError();
            }

            return { parse_res.TakeValue() };
        }

        template< Attribute... Attrs >
        ParseResult< std::tuple< detail::attrs::attr_return_type_t< Attrs >... > > ParseAttributes(
            Token last_tok) {
            std::tuple< std::optional< detail::attrs::attr_type_t< Attrs > >... > temp_results;

            while (true) {
                auto maybe_attr = ParseAttribute< Attrs... >(temp_results);
                if (!maybe_attr.Succeeded()) {
                    return maybe_attr.TakeError();
                }

                if (!maybe_attr.Value()) {
                    break;
                }

                last_tok = *maybe_attr.TakeValue();
            }

            auto missing_args = detail::attrs::check_missing_attrs< Attrs... >(temp_results);
            if (missing_args.has_value()) {
                return last_tok.GetPositionString() + ": " + *missing_args;
            }

            return detail::attrs::extract_results< Attrs... >(std::move(temp_results));
        }

        ParseResult< Region > ParseRegionSExpr();
        ParseResult< Region > ParseRegion();
        ParseResult< std::vector< Region > > ParseRegions();

        ParseResult< Function > ParseFunctionSExpr();
        ParseResult< Function > ParseFunction();

        ParseResult< std::pair< std::string, Token > > ParseExtIdentifer();

        ParseResult< LangDecl > ParseLDecl();

        ParseResult< Stmt > ParseStmt();
        ParseResult< Stmt > ParseStmtSExpr();

        struct Loc {
            Token ftoken;
            Token ltoken;
        };

        ParseResult< std::optional< LiteralPtr > > ParseLit();
        ParseResult< std::optional< LiteralPtr > > ParseLitSExpr();

        ParseResult< ExprPtr > ParseExpr();
        ParseResult< ExprPtr > ParseExprSExpr();
        ParseResult< ExprPtr > ParseBinSExpr(Token kind, Token lparen, BinaryOp op);
        ParseResult< ExprPtr > ParseCastSExpr(Token lparen, Token kind_tok, CastExprKind kind);

        ParseResult< TypePtr > ParseType();
        ParseResult< TypePtr > ParseTypeSExpr();

        ParseResult< Location > ParseRegisterLocationSExpr(Token lparen, Token kind_tok);
        ParseResult< Location > ParseMemoryLocationSExpr(Token lparen, Token kind_tok);
        ParseResult< Location > ParseIndirectMemoryLocationSExpr(Token lparen, Token kind_tok);
        ParseResult< Location > ParseLocationSExpr();
        ParseResult< Location > ParseLocation();
        ParseResult< StackOffset > ParseStackOffset();

        ParseResult< std::vector< LangDecl > > ParseDecls();
        ParseResult< std::vector< Stmt > > ParseSexprBody();

      public:
        Parser(gap::generator< ParseResult< Token > > tokens);

        ParseResult< PModule > ParseModule();
        ParseResult< std::vector< Stmt > > ParseRegionBody();
    };
} // namespace irene3::patchlang
