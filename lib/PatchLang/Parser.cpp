#include <anvill/Declarations.h>
#include <anvill/Type.h>
#include <glog/logging.h>
#include <irene3/PatchLang/Expr.h>
#include <irene3/PatchLang/Exprs.h>
#include <irene3/PatchLang/Lexer.h>
#include <irene3/PatchLang/Locations.h>
#include <irene3/PatchLang/Parser.h>
#include <irene3/PatchLang/Stmt.h>
#include <irene3/PatchLang/Type.h>
#include <irene3/PatchLang/Types.h>
#include <llvm/ADT/APFloat.h>
#include <llvm/ADT/APSInt.h>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#define ERR           std::stringstream()
#define STRINGIFY(x)  STRINGIFY_(x)
#define STRINGIFY_(x) #x
#define UNREACHABLE \
    return { "Reached the unreachable in " __FILE__ ":" STRINGIFY(__LINE__) }
#define CHECK_PARSE(name)                                                                  \
    do {                                                                                   \
        if (!name.Succeeded()) {                                                           \
            LOG(FATAL) << (ERR << "From " << __func__ << ":\n" << name.TakeError()).str(); \
        }                                                                                  \
    } while (false)
#define ATTR(klass, nm, ty)                               \
    struct klass {                                        \
        static constexpr const char* name = nm;           \
        static constexpr AttrKind kind    = AttrKind::ty; \
        static constexpr bool optional    = false;        \
    };
#define OPT_ATTR(klass, nm, ty)                           \
    struct klass {                                        \
        static constexpr const char* name = nm;           \
        static constexpr AttrKind kind    = AttrKind::ty; \
        static constexpr bool optional    = true;         \
    };

namespace irene3::patchlang
{
    Parser::Parser(gap::generator< Token > tokens)
        : tokens(std::move(tokens)) {}

    std::optional< Token > Parser::PeekToken() {
        if (!lookahead.has_value()) {
            lookahead = GetToken();
        }

        return lookahead;
    }

    std::optional< Token > Parser::GetToken() {
        if (lookahead.has_value()) {
            auto val  = *lookahead;
            lookahead = std::nullopt;
            return val;
        }

        auto tok_it = tokens.begin();
        if (tok_it == tokens.end()) {
            return std::nullopt;
        }
        auto tok = *tok_it;
        return tok;
    }

    static std::pair< const llvm::fltSemantics*, unsigned > getFltSemantics(
        const std::string_view str) {
        if (str == "f16") {
            return { &llvm::APFloatBase::IEEEhalf(), 16 };
        } else if (str == "bf16") {
            return { &llvm::APFloatBase::BFloat(), 16 };
        } else if (str == "f32") {
            return { &llvm::APFloatBase::IEEEsingle(), 32 };
        } else if (str == "f64") {
            return { &llvm::APFloatBase::IEEEdouble(), 64 };
        } else if (str == "f80") {
            return { &llvm::APFloatBase::x87DoubleExtended(), 80 };
        } else if (str == "f128") {
            return { &llvm::APFloatBase::IEEEquad(), 128 };
        } else if (str == "f8e5m2") {
            return { &llvm::APFloatBase::Float8E5M2(), 8 };
        } else if (str == "f8e5m2fnuz") {
            return { &llvm::APFloatBase::Float8E5M2FNUZ(), 8 };
        } else if (str == "f8e4m3fn") {
            return { &llvm::APFloatBase::Float8E4M3FN(), 8 };
        } else if (str == "f8e4m3fnuz") {
            return { &llvm::APFloatBase::Float8E4M3FNUZ(), 8 };
        } else if (str == "f8e4m3b11fnuz") {
            return { &llvm::APFloatBase::Float8E4M3B11FNUZ(), 8 };
        } else if (str == "tf32") {
            return { &llvm::APFloatBase::FloatTF32(), 32 };
        } else {
            throw std::logic_error("invalid floating point type");
        }
    }

    ParseResult< FloatLitExpr > Parser::ParseFloatLit() {
        auto tok = GetToken< Token::HexFloatLit >();
        CHECK_PARSE(tok);

        std::string_view view = tok->contents;

        std::string_view bitwidth_view = view;
        // Remove everything up before ':'
        while (bitwidth_view[0] != ':') {
            bitwidth_view.remove_prefix(1);
        }
        bitwidth_view.remove_prefix(1);
        auto [sema, bitwidth] = getFltSemantics(bitwidth_view);

        llvm::APInt value(bitwidth, 0);

        // skip 0x
        view.remove_prefix(2);
        while (true) {
            auto c = view[0];
            if (c == ':') {
                break;
            }
            uint64_t digit;
            if (c >= '0' && c <= '9') {
                digit = static_cast< uint64_t >(c - '0');
            } else if (c >= 'A' && c <= 'F') {
                digit = static_cast< uint64_t >(c - 'A') + 10;
            } else {
                assert(c >= 'a' && c <= 'f');
                digit = static_cast< uint64_t >(c - 'a') + 10;
            }
            value = (value << 4) | digit;
            view.remove_prefix(1);
        }

        return FloatLitExpr(llvm::APFloat(*sema, value), tok.TakeValue());
    }

    ParseResult< IntLitExpr > Parser::ParseIntLit() {
        auto tok
            = GetToken< Token::BinIntLit, Token::OctIntLit, Token::DecIntLit, Token::HexIntLit >();
        CHECK_PARSE(tok);

        std::string_view view = tok->contents;

        unsigned bitwidth = 0;
        {
            std::string_view bitwidth_view = view;
            // Remove everything up before ':'
            while (bitwidth_view[0] != ':') {
                bitwidth_view.remove_prefix(1);
            }
            bitwidth_view.remove_prefix(1);
            for (auto c : bitwidth_view) {
                bitwidth = (bitwidth * 10) + static_cast< unsigned >(c - '0');
            }
        }

        llvm::APSInt value(bitwidth);
        bool is_negative = false;
        if (view[0] == '-' || view[0] == '+') {
            value.setIsSigned(true);
            is_negative = view[0] == '-';
            view.remove_prefix(1);
        }

        LitBase base;
        switch (tok->kind) {
            case Token::BinIntLit: {
                base = LitBase::Binary;
                view.remove_prefix(2);
                while (true) {
                    auto c = view[0];
                    if (c == ':') {
                        break;
                    }
                    value = (value << 1) | static_cast< uint64_t >(c - '0');
                    view.remove_prefix(1);
                }
            } break;
            case Token::OctIntLit: {
                base = LitBase::Octal;
                view.remove_prefix(1);
                while (true) {
                    auto c = view[0];
                    if (c == ':') {
                        break;
                    }
                    value = (value << 3) | static_cast< uint64_t >(c - '0');
                    view.remove_prefix(1);
                }
            } break;
            case Token::DecIntLit: {
                base = LitBase::Decimal;
                while (true) {
                    auto c = view[0];
                    if (c == ':') {
                        break;
                    }
                    value = (value * 10) + static_cast< uint64_t >(c - '0');
                    view.remove_prefix(1);
                }
            } break;
            case Token::HexIntLit: {
                base = LitBase::Hexadecimal;
                view.remove_prefix(2);
                while (true) {
                    auto c = view[0];
                    if (c == ':') {
                        break;
                    }
                    uint64_t digit;
                    if (c >= '0' && c <= '9') {
                        digit = static_cast< uint64_t >(c - '0');
                    } else if (c >= 'A' && c <= 'F') {
                        digit = static_cast< uint64_t >(c - 'A') + 10;
                    } else {
                        assert(c >= 'a' && c <= 'f');
                        digit = static_cast< uint64_t >(c - 'a') + 10;
                    }
                    value = (value << 4) | digit;
                    view.remove_prefix(1);
                }
            } break;
            default:
                assert(0);
                base = LitBase::Decimal;
                break;
        }

        if (is_negative) {
            value = -value;
        }

        return IntLitExpr(value, base, tok.TakeValue());
    }

    ParseResult< BoolLitExpr > Parser::ParseBexpr() {
        auto tlit = GetIdent({ "true", "false" });
        CHECK_PARSE(tlit);

        auto v = tlit->contents == "true";
        return BoolLitExpr(v, tlit.TakeValue());
    }

    static std::string UnescapeString(std::string_view view) {
        std::stringstream str;
        // remove leading and trailing "
        view.remove_prefix(1);
        view.remove_suffix(1);
        while (!view.empty()) {
            if (view.front() == '\\') {
                view.remove_prefix(1);
                char front = view.front();
                switch (front) {
                    case 'a': str << '\a'; break;
                    case 'b': str << '\b'; break;
                    case 'f': str << '\f'; break;
                    case 'n': str << '\n'; break;
                    case 'r': str << '\r'; break;
                    case 't': str << '\t'; break;
                    case '\\': str << '\\'; break;
                    case 'x': {
                        view.remove_prefix(1);
                        char chr = 0;
                        while (true) {
                            front = view.front();
                            if (front >= '0' && front <= '9') {
                                chr <<= 4;
                                chr |= (front - '0');
                                view.remove_prefix(1);
                            } else if (front >= 'a' && front <= 'f') {
                                chr <<= 4;
                                chr |= (front - 'a' + 10);
                                view.remove_prefix(1);
                            } else if (front >= 'A' && front <= 'F') {
                                chr <<= 4;
                                chr |= (front - 'A' + 10);
                                view.remove_prefix(1);
                            } else {
                                break;
                            }
                        }
                        str << chr;
                    } break;
                    default: { // Octal character
                        char chr = front - '0';
                        view.remove_prefix(1);
                        front = view.front();
                        view.remove_prefix(1);
                        if (!(front >= '0' && front <= '9')) {
                            str << chr;
                            break;
                        }

                        chr <<= 3;
                        chr |= front - '0';
                        view.remove_prefix(1);
                        front = view.front();
                        if (!(front >= '0' && front <= '9')) {
                            str << chr;
                            break;
                        }

                        chr <<= 3;
                        chr |= front - '0';
                        view.remove_prefix(1);
                        front = view.front();
                        str << chr;
                    } break;
                }
            } else {
                str << view.front();
            }
            view.remove_prefix(1);
        }
        return str.str();
    }

    ParseResult< StrLitExpr > Parser::ParseStrLit() {
        auto tok = GetToken< Token::StrLit >();
        CHECK_PARSE(tok);
        return StrLitExpr(UnescapeString(tok->contents), tok.TakeValue());
    }

    ParseResult< Region > Parser::ParseRegion() {
        auto tok = PeekToken< Token::LParen >();
        CHECK_PARSE(tok);

        if (tok->kind == Token::LParen) {
            return ParseRegionSExpr();
        }

        return (ERR << tok->GetPositionString() << ": Unexpected token `" << tok->contents
                    << "` while parsing a region")
            .str();
    }

    namespace region_attrs
    {
        ATTR(AddressAttr, "address", IntLit)
        ATTR(SizeAttr, "size", IntLit)
        ATTR(StackOffsetEntryAttr, "stack_offset_at_entry", IntLit)
        ATTR(StackOffsetExitAttr, "stack_offset_at_exit", IntLit)
        ATTR(UIDAttr, "region_uid", IntLit)
    }; // namespace region_attrs

    ParseResult< Region > Parser::ParseRegionSExpr() {
        auto lparen = GetToken< Token::LParen >();
        CHECK_PARSE(lparen);

        auto maybe_region = GetIdent({ "region" });
        CHECK_PARSE(maybe_region);

        using namespace region_attrs;
        auto attrs = ParseAttributes<
            AddressAttr, SizeAttr, StackOffsetEntryAttr, StackOffsetExitAttr, UIDAttr >();
        CHECK_PARSE(attrs);
        auto [address, size, stack_offset_at_entry, stack_offset_at_exit, uid] = attrs.TakeValue();

        std::vector< Stmt > body;
        while (true) {
            auto peek = PeekToken();
            if (!peek.has_value()) {
                return { "Unexpected EOF while parsing BlockSExpr" };
            }
            if (peek->kind == Token::RParen) {
                break;
            }

            auto stmt = ParseStmt();
            if (!stmt.Succeeded()) {
                return stmt.TakeError();
            }
            body.emplace_back(stmt.TakeValue());
        }

        auto rparen = GetToken< Token::RParen >();
        CHECK_PARSE(rparen);

        return Region(
            std::move(body), std::move(address), std::move(size), std::move(stack_offset_at_entry),
            std::move(stack_offset_at_exit), std::move(uid), lparen.TakeValue(),
            rparen.TakeValue());
    }

    ParseResult< std::vector< Region > > Parser::ParseRegions() {
        std::vector< Region > regions;
        while (true) {
            auto region = ParseRegion();
            CHECK_PARSE(region);
            regions.push_back(region.TakeValue());

            auto peek = PeekToken();
            if (!peek.has_value() || peek->kind == Token::RParen || peek->kind == Token::RBrace) {
                break;
            }
        }
        return regions;
    }

    namespace func_attrs
    {
        ATTR(NameAttr, "name", ExternalName)
        ATTR(AddressAttr, "address", IntLit)
        ATTR(DispAttr, "displacement", IntLit)
        ATTR(IsExternAttr, "is_external", BoolLit)
        ATTR(BitSizeAttr, "bit_size", IntLit)
    }; // namespace func_attrs

    ParseResult< Function > Parser::ParseFunctionSExpr() {
        using namespace func_attrs;

        auto lparen = GetToken< Token::LParen >();
        CHECK_PARSE(lparen);

        auto region = GetIdent({ "function" });
        CHECK_PARSE(region);

        auto attrs = ParseAttributes< NameAttr, AddressAttr, DispAttr, IsExternAttr >();
        CHECK_PARSE(attrs);

        auto [func_name, func_addr, disp, is_ext] = attrs.TakeValue();
        std::string name                          = std::string(func_name.contents);
        if (func_name.kind == Token::StrLit) {
            name = UnescapeString(name);
        }

        auto regions = ParseRegions();
        CHECK_PARSE(regions);

        auto rparen = GetToken< Token::RParen >();
        CHECK_PARSE(rparen);

        return Function(
            regions.TakeValue(), std::move(func_addr), std::move(disp), std::move(is_ext), name,
            func_name, lparen.TakeValue(), rparen.TakeValue());
    }

    ParseResult< Function > Parser::ParseFunction() {
        auto tok = PeekToken< Token::LParen >();
        CHECK_PARSE(tok);

        if (tok->kind == Token::LParen) {
            return ParseFunctionSExpr();
        }

        return (ERR << tok->GetPositionString() << ": Unexpected token `" << tok->contents
                    << "` while parsing a function")
            .str();
    }

    ParseResult< std::pair< std::string, Token > > Parser::ParseExtIdentifer() {
        auto tok = PeekToken< Token::Ident, Token::StrLit >();
        CHECK_PARSE(tok);

        std::string nm;
        if (tok->kind == Token::StrLit) {
            auto v = this->ParseStrLit();
            CHECK_PARSE(v);
            nm = v.TakeValue().GetValue();
        } else {
            auto res = this->GetToken< Token::Ident >();
            CHECK_PARSE(res);
            nm = res.TakeValue().contents;
        }

        return {
            {nm, tok.TakeValue()}
        };
    }

    ParseResult< LangDecl > Parser::ParseLDecl() {
        using namespace func_attrs;

        auto lparen = GetToken< Token::LParen >();
        CHECK_PARSE(lparen);

        auto ident = GetIdent({ "function", "external", "external_global", "type_decl" });
        CHECK_PARSE(ident);

        if (ident->contents == "type_decl") {
            auto ext_id = this->ParseExtIdentifer();
            CHECK_PARSE(ext_id);
            auto [nm, tok] = ext_id.TakeValue();
            auto ty        = ParseType();
            CHECK_PARSE(ty);
            auto rparen = GetToken< Token::RParen >();
            CHECK_PARSE(rparen);
            return { TypeDecl(nm, ty.TakeValue(), tok, lparen.TakeValue(), rparen.TakeValue()) };
        }

        std::optional< Token > func_name;
        std::optional< IntLitExpr > func_addr;
        std::optional< IntLitExpr > disp;
        std::optional< BoolLitExpr > is_ext;
        std::optional< IntLitExpr > bit_size;
        if (ident->contents != "external_global") {
            auto attrs = ParseAttributes< NameAttr, AddressAttr, DispAttr, IsExternAttr >();
            CHECK_PARSE(attrs);

            auto [func_name_i, func_addr_i, disp_i, is_ext_i] = attrs.TakeValue();
            func_name                                         = func_name_i;
            func_addr                                         = func_addr_i;
            disp                                              = disp_i;
            is_ext                                            = is_ext_i;
        } else {
            auto attrs
                = ParseAttributes< NameAttr, AddressAttr, DispAttr, IsExternAttr, BitSizeAttr >();
            CHECK_PARSE(attrs);

            auto [func_name_i, func_addr_i, disp_i, is_ext_i, bit_size_i] = attrs.TakeValue();
            func_name                                                     = func_name_i;
            func_addr                                                     = func_addr_i;
            disp                                                          = disp_i;
            is_ext                                                        = is_ext_i;
            bit_size                                                      = bit_size_i;
        }
        std::string name = std::string(func_name->contents);
        if (func_name->kind == Token::StrLit) {
            name = UnescapeString(name);
        }

        ParseResult< std::vector< Region > > regions;
        if (ident->contents == "function") {
            regions = ParseRegions();
            CHECK_PARSE(regions);
        }

        std::vector< TypePtr > typerange;
        ParseResult< TypePtr > retty;
        if (ident->contents == "external") {
            retty = ParseType();
            CHECK_PARSE(retty);

            while (true) {
                auto prs = PeekToken();
                if (!prs) {
                    return { "Unexpected EOF while parsing ParseStmtSExpr" };
                }

                if (prs->kind == TokenKind::RParen) {
                    break;
                }

                auto ty = ParseType();
                CHECK_PARSE(ty);
                typerange.push_back(ty.TakeValue());
            }
        }

        ParseResult< TypePtr > gv_ty;
        if (ident->contents == "external_global") {
            gv_ty = ParseType();
            CHECK_PARSE(gv_ty);
        }

        auto rparen = GetToken< Token::RParen >();
        CHECK_PARSE(rparen);

        if (ident->contents == "function") {
            return { Function(
                regions.TakeValue(), std::move(*func_addr), std::move(*disp), std::move(*is_ext),
                name, *func_name, lparen.TakeValue(), rparen.TakeValue()) };
        } else if (ident->contents == "external") {
            return { External(
                std::move(*func_addr), std::move(*disp), std::move(*is_ext), name,
                retty.TakeValue(), std::move(typerange), *func_name, lparen.TakeValue(),
                rparen.TakeValue()) };
        } else {
            return { ExternalGlobal(
                std::move(*func_addr), std::move(*disp), std::move(*is_ext), std::move(*bit_size),
                name, gv_ty.TakeValue(), *func_name, lparen.TakeValue(), rparen.TakeValue()) };
        }
    }

    ParseResult< std::vector< LangDecl > > Parser::ParseDecls() {
        std::vector< LangDecl > functions;
        while (true) {
            auto tok = PeekToken();
            if (!tok.has_value() || tok->kind == Token::RParen) {
                break;
            }
            auto func = ParseLDecl();

            CHECK_PARSE(func);

            functions.push_back(func.TakeValue());
        }
        return std::move(functions);
    }

    namespace module_attrs
    {
        ATTR(TripletAttr, "triplet", StrLit)
        ATTR(DataLayoutAttr, "layout", StrLit)
        ATTR(ImageBaseAttr, "image_base", IntLit)
    } // namespace module_attrs
    ParseResult< PModule > Parser::ParseModule() {
        using namespace module_attrs;
        auto op = GetToken< TokenKind::LParen >();
        CHECK_PARSE(op);
        auto mod = GetIdent({ "module" });
        CHECK_PARSE(mod);

        auto attrs = ParseAttributes< TripletAttr, DataLayoutAttr, ImageBaseAttr >();
        CHECK_PARSE(attrs);
        auto [triplet, datalayout, imgbase] = attrs.TakeValue();

        auto decls = this->ParseDecls();
        CHECK_PARSE(decls);

        auto close = GetToken< TokenKind::RParen >();
        CHECK_PARSE(close);
        return PModule(
            std::move(datalayout), std::move(triplet), std::move(imgbase), (decls.TakeValue()),
            op.TakeValue(), close.TakeValue());
    }

    ParseResult< Stmt > Parser::ParseStmt() {
        auto tok = PeekToken< Token::LParen >();
        CHECK_PARSE(tok);

        if (tok->kind == Token::LParen) {
            return ParseStmtSExpr();
        }

        return (ERR << tok->GetPositionString() << ": Unexpected token `" << tok->contents
                    << "` while parsing a statement")
            .str();
    }

    namespace mem_attrs
    {
        OPT_ATTR(IsVolatileAttr, "is_volatile", BoolLit)
    }

    namespace stmt_attrs
    {
        ATTR(CalleeAttr, "callee", StrLit)
        ATTR(TypeAttr, "type", Type)
        OPT_ATTR(AtEntryAttr, "at_entry", Location)
        OPT_ATTR(AtExitAttr, "at_exit", Location)
    } // namespace stmt_attrs

    ParseResult< Stmt > Parser::ParseStmtSExpr() {
        auto lparen = GetToken< Token::LParen >();
        CHECK_PARSE(lparen);

        auto stmt_kind = GetIdent({
            "let",
            "store",
            "return",
            "call",
            "intrinsic",
            "value",
            "goto",
            "cond_goto",
            "nop",
        });

        CHECK_PARSE(stmt_kind);

        if (stmt_kind->contents == "let") {
            auto name = GetToken< Token::Ident >();
            CHECK_PARSE(name);

            auto value = ParseExpr();
            CHECK_PARSE(value);

            auto rparen = GetToken< TokenKind::RParen >();
            CHECK_PARSE(rparen);

            return { LetDeclStmt(
                std::string(name->contents),
                std::make_unique< Expr >(std::move(*value.TakeValue())), lparen.TakeValue(),
                rparen.TakeValue()) };
        } else if (stmt_kind->contents == "store") {
            auto volatile_attr = ParseAttributes< mem_attrs::IsVolatileAttr >();
            CHECK_PARSE(volatile_attr);
            std::optional< BoolLitExpr > is_vol = std::get< 0 >(volatile_attr.TakeValue());

            auto value = ParseExpr();
            CHECK_PARSE(value);

            auto dest = ParseExpr();
            CHECK_PARSE(dest);

            auto rparen = GetToken< TokenKind::RParen >();
            CHECK_PARSE(rparen);

            return { StoreStmt(
                std::make_unique< Expr >(std::move(*value.TakeValue())),
                std::make_unique< Expr >(std::move(*dest.TakeValue())),
                is_vol ? is_vol->GetValue() : false, lparen.TakeValue(), rparen.TakeValue()) };
        } else if (stmt_kind->contents == "return") {
            auto maybe_rparen = PeekToken();
            if (maybe_rparen && maybe_rparen->kind == Token::RParen) {
                GetToken();
                return { ReturnStmt(lparen.TakeValue(), *maybe_rparen) };
            }

            auto value = ParseExpr();
            CHECK_PARSE(value);

            auto rparen = GetToken< TokenKind::RParen >();
            CHECK_PARSE(rparen);

            return { ReturnStmt(
                std::move(*value.TakeValue()), lparen.TakeValue(), rparen.TakeValue()) };
        } else if (stmt_kind->contents == "call") {
            using namespace stmt_attrs;
            auto attrs = ParseAttributes< CalleeAttr >();
            CHECK_PARSE(attrs);

            auto [callee] = attrs.TakeValue();

            std::vector< ExprPtr > args;
            while (true) {
                auto rparen = PeekToken();
                if (!rparen) {
                    return { "Unexpected EOF while parsing ParseStmtSExpr" };
                }

                if (rparen->kind == Token::RParen) {
                    GetToken();
                    return { CallStmt(
                        std::move(callee), std::move(args), lparen.TakeValue(), *rparen) };
                }

                auto arg = ParseExpr();
                CHECK_PARSE(arg);
                args.emplace_back(arg.TakeValue());
            }
        } else if (stmt_kind->contents == "intrinsic") {
            using namespace stmt_attrs;
            auto attrs = ParseAttributes< CalleeAttr >();
            CHECK_PARSE(attrs);

            auto [callee] = attrs.TakeValue();

            std::vector< ExprPtr > args;
            while (true) {
                auto rparen = PeekToken();
                if (!rparen) {
                    return { "Unexpected EOF while parsing ParseStmtSExpr" };
                }

                if (rparen->kind == Token::RParen) {
                    GetToken();
                    return { CallIntrinsicStmt(
                        std::move(callee), std::move(args), lparen.TakeValue(), *rparen) };
                }

                auto arg = ParseExpr();
                CHECK_PARSE(arg);
                args.emplace_back(arg.TakeValue());
            }
        } else if (stmt_kind->contents == "value") {
            using namespace stmt_attrs;
            auto name = GetToken< Token::Ident >();
            CHECK_PARSE(name);

            auto ty = this->ParseType();
            CHECK_PARSE(ty);

            auto maybe_attrs = ParseAttributes< AtEntryAttr, AtExitAttr >();
            CHECK_PARSE(maybe_attrs);

            auto [at_entry, at_exit] = maybe_attrs.TakeValue();

            auto rparen = GetToken< Token::RParen >();
            CHECK_PARSE(rparen);

            auto name_tok = name.TakeValue();

            return { ValueStmt(
                std::string(name_tok.contents), std::move(at_entry), std::move(at_exit),
                ty.TakeValue(), name_tok, lparen.TakeValue(), rparen.TakeValue()) };
        } else if (stmt_kind->contents == "goto") {
            auto target = ParseIntLit();
            CHECK_PARSE(target);

            auto rparen = GetToken< Token::RParen >();
            CHECK_PARSE(rparen);

            return { GotoStmt(target.TakeValue(), lparen.TakeValue(), rparen.TakeValue()) };
        } else if (stmt_kind->contents == "cond_goto") {
            auto target = ParseIntLit();
            CHECK_PARSE(target);

            auto exp = ParseExpr();
            CHECK_PARSE(exp);

            auto rparen = GetToken< Token::RParen >();
            CHECK_PARSE(rparen);

            return { ConditionalGotoStmt(
                target.TakeValue(), exp.TakeValue(), lparen.TakeValue(), rparen.TakeValue()) };
        } else if (stmt_kind->contents == "nop") {
            auto rparen = GetToken< Token::RParen >();
            CHECK_PARSE(rparen);

            return { NopStmt(lparen.TakeValue(), rparen.TakeValue()) };
        }

        UNREACHABLE;
    }

    ParseResult< ExprPtr > Parser::ParseExpr() {
        auto maybe_lit = MaybeGetIdent({ "null", "true", "false" });
        CHECK_PARSE(maybe_lit);

        if (maybe_lit->has_value()) {
            auto lit = *maybe_lit.TakeValue();
            if (lit.contents == "null") {
                return MakeExpr< NullExpr >(lit, lit);
            } else if (lit.contents == "true" || lit.contents == "false") {
                return MakeExpr< BoolLitExpr >(lit.contents == "true", lit);
            }
        }

        auto tok = PeekToken<
            Token::LParen, Token::BinIntLit, Token::OctIntLit, Token::DecIntLit, Token::HexIntLit,
            Token::Ident >();
        CHECK_PARSE(tok);
        switch (tok->kind) {
            case Token::BinIntLit:
            case Token::OctIntLit:
            case Token::DecIntLit:
            case Token::HexIntLit: {
                auto lit = ParseIntLit();
                CHECK_PARSE(lit);
                return { std::make_unique< Expr >(lit.TakeValue()) };
            }
            case Token::HexFloatLit: {
                auto lit = ParseFloatLit();
                CHECK_PARSE(lit);
                return { std::make_unique< Expr >(lit.TakeValue()) };
            }
            case Token::LParen: return ParseExprSExpr();
            case Token::Ident: {
                auto tok  = GetToken();
                auto name = tok.value();

                return MakeExpr< DeclRefExpr >(std::string(name.contents), name, name, name);
            }
            default: UNREACHABLE;
        }
    }

    namespace expr_attrs
    {
        ATTR(CalleeAttr, "callee", StrLit)
        ATTR(AlignmentAttr, "alignment", IntLit)
        ATTR(TypeAttr, "type", Type)
        ATTR(ArraySize, "arraySize", Expr)

        ATTR(CondAttr, "cond", Expr)
        ATTR(IfTrueAttr, "if_true", Expr)
        ATTR(IfFalseAttr, "if_false", Expr)
    } // namespace expr_attrs

    ParseResult< ExprPtr > Parser::ParseBinSExpr(Token kind, Token lparen, BinaryOp op) {
        auto lhs = ParseExpr();
        CHECK_PARSE(lhs);

        auto rhs = ParseExpr();
        CHECK_PARSE(rhs);

        auto rparen = GetToken< Token::RParen >();
        CHECK_PARSE(rparen);

        return MakeExpr< BinaryExpr >(
            op, kind, lhs.TakeValue(), rhs.TakeValue(), lparen, rparen.TakeValue());
    }

    ParseResult< ExprPtr > Parser::ParseCastSExpr(Token lparen, CastExprKind kind) {
        using namespace expr_attrs;
        auto attrs = ParseAttributes< TypeAttr >();
        CHECK_PARSE(attrs);

        auto [type] = attrs.TakeValue();

        auto ptr = ParseExpr();
        CHECK_PARSE(ptr);

        auto rparen = GetToken< Token::RParen >();
        CHECK_PARSE(rparen);

        return MakeExpr< CastExpr >(
            std::move(type), ptr.TakeValue(), kind, lparen, rparen.TakeValue());
    }

    ParseResult< ExprPtr > Parser::ParseExprSExpr() {
        using namespace expr_attrs;
        auto lparen = GetToken< Token::LParen >();
        CHECK_PARSE(lparen);

        auto kind = GetIdent({ "getelementptr",
                               "call",
                               "intrinsic",
                               "alloca",
                               "load",
                               "add",
                               "fadd",
                               "sub",
                               "fsub",
                               "mul",
                               "fmul",
                               "udiv",
                               "sdiv",
                               "fdiv",
                               "urem",
                               "srem",
                               "frem",
                               "shl",
                               "lshr",
                               "ashr",
                               "and",
                               "or",
                               "xor",
                               "ptrtoint",
                               "trunc",
                               "zext",
                               "sext",
                               "fptrunc",
                               "fpext",
                               "fptoui",
                               "fptosi",
                               "uitofp",
                               "sitofp",
                               "inttoptr",
                               "bitcast",
                               "select",

                               "eq",
                               "ne",
                               "ugt",
                               "uge",
                               "ult",
                               "ule",
                               "sgt",
                               "sge",
                               "slt",
                               "sle",

                               "foeq",
                               "fogt",
                               "foge",
                               "folt",
                               "fole",
                               "fone",
                               "ford",
                               "fueq",
                               "fugt",
                               "fuge",
                               "fult",
                               "fule",
                               "fune",
                               "funo",

                               "addrof" });
        CHECK_PARSE(kind);

        if (kind->contents == "getelementptr") {
            auto base = ParseExpr();
            CHECK_PARSE(base);

            auto elem_type = ParseType();
            CHECK_PARSE(elem_type);

            std::vector< ExprPtr > indices;
            while (true) {
                auto index = ParseExpr();
                CHECK_PARSE(index);
                indices.emplace_back(index.TakeValue());

                auto rparen = PeekToken();
                if (!rparen) {
                    return { "Unexpected EOF while parsing ParseExprSExpr" };
                }

                if (rparen->kind == Token::RParen) {
                    break;
                }
            }

            auto rparen = GetToken< Token::RParen >();
            CHECK_PARSE(rparen);

            return MakeExpr< GetElementPtrExpr >(
                base.TakeValue(), elem_type.TakeValue(), std::move(indices), lparen.TakeValue(),
                rparen.TakeValue());
        } else if (kind->contents == "call") {
            auto attrs = ParseAttributes< CalleeAttr >();
            CHECK_PARSE(attrs);

            auto [callee] = attrs.TakeValue();

            std::vector< ExprPtr > args;
            while (true) {
                auto rparen = PeekToken();
                if (!rparen) {
                    return { "Unexpected EOF while parsing ParseExprSExpr" };
                }

                if (rparen->kind == Token::RParen) {
                    GetToken();
                    return MakeExpr< CallExpr >(
                        std::move(callee), std::move(args), lparen.TakeValue(), *rparen);
                }

                auto arg = ParseExpr();
                CHECK_PARSE(arg);
                args.emplace_back(arg.TakeValue());
            }
        } else if (kind->contents == "intrinsic") {
            auto attrs = ParseAttributes< CalleeAttr >();
            CHECK_PARSE(attrs);

            auto [callee] = attrs.TakeValue();

            std::vector< ExprPtr > args;
            while (true) {
                auto rparen = PeekToken();
                if (!rparen) {
                    return { "Unexpected EOF while parsing ParseExprSExpr" };
                }

                if (rparen->kind == Token::RParen) {
                    GetToken();
                    return MakeExpr< CallIntrinsicExpr >(
                        std::move(callee), std::move(args), lparen.TakeValue(), *rparen);
                }

                auto arg = ParseExpr();
                CHECK_PARSE(arg);
                args.emplace_back(arg.TakeValue());
            }
        } else if (kind->contents == "alloca") {
            auto attrs = ParseAttributes< AlignmentAttr, TypeAttr, ArraySize >();
            CHECK_PARSE(attrs);

            auto [alignment, type, arraySize] = attrs.TakeValue();
            auto rparen                       = GetToken< Token::RParen >();
            CHECK_PARSE(rparen);

            return MakeExpr< AllocaExpr >(
                std::move(arraySize), std::move(alignment), std::move(type), lparen.TakeValue(),
                rparen.TakeValue());
        } else if (kind->contents == "load") {
            auto attrs = ParseAttributes< TypeAttr, mem_attrs::IsVolatileAttr >();
            CHECK_PARSE(attrs);

            auto [type, is_vol] = attrs.TakeValue();

            auto ptr = ParseExpr();
            CHECK_PARSE(ptr);

            auto rparen = GetToken< Token::RParen >();
            CHECK_PARSE(rparen);

            return MakeExpr< LoadExpr >(
                std::move(type), is_vol ? is_vol->GetValue() : false, ptr.TakeValue(),
                lparen.TakeValue(), rparen.TakeValue());
        } else if (kind->contents == "add") {
            auto nuw = MaybeGetIdent({ "nuw" });
            CHECK_PARSE(nuw);

            auto nsw = MaybeGetIdent({ "nsw" });
            CHECK_PARSE(nsw);

            auto lhs = ParseExpr();
            CHECK_PARSE(lhs);

            auto rhs = ParseExpr();
            CHECK_PARSE(rhs);

            auto rparen = GetToken< Token::RParen >();
            CHECK_PARSE(rparen);

            unsigned op = BinaryOp::Add;
            op |= nuw->has_value() ? Nuw : 0;
            op |= nsw->has_value() ? Nsw : 0;
            return MakeExpr< BinaryExpr >(
                static_cast< BinaryOp >(op), kind.TakeValue(), lhs.TakeValue(), rhs.TakeValue(),
                lparen.TakeValue(), rparen.TakeValue());
        } else if (kind->contents == "sub") {
            auto nuw = MaybeGetIdent({ "nuw" });
            CHECK_PARSE(nuw);

            auto nsw = MaybeGetIdent({ "nsw" });
            CHECK_PARSE(nsw);

            auto lhs = ParseExpr();
            CHECK_PARSE(lhs);

            auto rhs = ParseExpr();
            CHECK_PARSE(rhs);

            auto rparen = GetToken< Token::RParen >();
            CHECK_PARSE(rparen);

            unsigned op = BinaryOp::Sub;
            op |= nuw->has_value() ? Nuw : 0;
            op |= nsw->has_value() ? Nsw : 0;
            return MakeExpr< BinaryExpr >(
                static_cast< BinaryOp >(op), kind.TakeValue(), lhs.TakeValue(), rhs.TakeValue(),
                lparen.TakeValue(), rparen.TakeValue());
        } else if (kind->contents == "mul") {
            auto nuw = MaybeGetIdent({ "nuw" });
            CHECK_PARSE(nuw);

            auto nsw = MaybeGetIdent({ "nsw" });
            CHECK_PARSE(nsw);

            auto lhs = ParseExpr();
            CHECK_PARSE(lhs);

            auto rhs = ParseExpr();
            CHECK_PARSE(rhs);

            auto rparen = GetToken< Token::RParen >();
            CHECK_PARSE(rparen);

            unsigned op = BinaryOp::Mul;
            op |= nuw->has_value() ? Nuw : 0;
            op |= nsw->has_value() ? Nsw : 0;
            return MakeExpr< BinaryExpr >(
                static_cast< BinaryOp >(op), kind.TakeValue(), lhs.TakeValue(), rhs.TakeValue(),
                lparen.TakeValue(), rparen.TakeValue());
        } else if (kind->contents == "shl") {
            auto nuw = MaybeGetIdent({ "nuw" });
            CHECK_PARSE(nuw);

            auto nsw = MaybeGetIdent({ "nsw" });
            CHECK_PARSE(nsw);

            auto lhs = ParseExpr();
            CHECK_PARSE(lhs);

            auto rhs = ParseExpr();
            CHECK_PARSE(rhs);

            auto rparen = GetToken< Token::RParen >();
            CHECK_PARSE(rparen);

            unsigned op = BinaryOp::Shl;
            op |= nuw->has_value() ? Nuw : 0;
            op |= nsw->has_value() ? Nsw : 0;
            return MakeExpr< BinaryExpr >(
                static_cast< BinaryOp >(op), kind.TakeValue(), lhs.TakeValue(), rhs.TakeValue(),
                lparen.TakeValue(), rparen.TakeValue());
        } else if (kind->contents == "fadd") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Fadd);
        } else if (kind->contents == "fsub") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Fsub);
        } else if (kind->contents == "fmul") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Fmul);
        } else if (kind->contents == "udiv") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Udiv);
        } else if (kind->contents == "sdiv") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Sdiv);
        } else if (kind->contents == "fdiv") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Fdiv);
        } else if (kind->contents == "srem") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Srem);
        } else if (kind->contents == "frem") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Frem);
        } else if (kind->contents == "lshr") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Lshr);
        } else if (kind->contents == "ashr") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Ashr);
        } else if (kind->contents == "and") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::And);
        } else if (kind->contents == "or") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Or);
        } else if (kind->contents == "xor") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Xor);
        } else if (kind->contents == "ptrtoint") {
            return ParseCastSExpr(lparen.TakeValue(), CastExpr::PtrToInt);
        } else if (kind->contents == "trunc") {
            return ParseCastSExpr(lparen.TakeValue(), CastExpr::Trunc);
        } else if (kind->contents == "zext") {
            return ParseCastSExpr(lparen.TakeValue(), CastExpr::ZExt);
        } else if (kind->contents == "sext") {
            return ParseCastSExpr(lparen.TakeValue(), CastExpr::SExt);
        } else if (kind->contents == "fptrunc") {
            return ParseCastSExpr(lparen.TakeValue(), CastExpr::FPTrunc);
        } else if (kind->contents == "fpext") {
            return ParseCastSExpr(lparen.TakeValue(), CastExpr::FPExt);
        } else if (kind->contents == "fptoui") {
            return ParseCastSExpr(lparen.TakeValue(), CastExpr::FPToUI);
        } else if (kind->contents == "fptosi") {
            return ParseCastSExpr(lparen.TakeValue(), CastExpr::FPToSI);
        } else if (kind->contents == "uitofp") {
            return ParseCastSExpr(lparen.TakeValue(), CastExpr::UIToFP);
        } else if (kind->contents == "sitofp") {
            return ParseCastSExpr(lparen.TakeValue(), CastExpr::SIToFP);
        } else if (kind->contents == "inttoptr") {
            return ParseCastSExpr(lparen.TakeValue(), CastExpr::IntToPtr);
        } else if (kind->contents == "bitcast") {
            return ParseCastSExpr(lparen.TakeValue(), CastExpr::BitCast);
        } else if (kind->contents == "select") {
            auto attrs = ParseAttributes< CondAttr, IfTrueAttr, IfFalseAttr >();
            CHECK_PARSE(attrs);

            auto [cond, if_true, if_false] = attrs.TakeValue();
            auto rparen                    = GetToken< Token::RParen >();
            CHECK_PARSE(rparen);

            return MakeExpr< SelectExpr >(
                std::move(cond), std::move(if_true), std::move(if_false), lparen.TakeValue(),
                rparen.TakeValue());
        } else if (kind->contents == "eq") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Eq);
        } else if (kind->contents == "ne") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Ne);
        } else if (kind->contents == "ugt") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Ugt);
        } else if (kind->contents == "uge") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Uge);
        } else if (kind->contents == "ult") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Ult);
        } else if (kind->contents == "ule") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Ule);
        } else if (kind->contents == "sgt") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Sgt);
        } else if (kind->contents == "sge") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Sge);
        } else if (kind->contents == "slt") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Slt);
        } else if (kind->contents == "sle") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Sle);
        } else if (kind->contents == "foeq") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Foeq);
        } else if (kind->contents == "fogt") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Fogt);
        } else if (kind->contents == "foge") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Foge);
        } else if (kind->contents == "folt") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Folt);
        } else if (kind->contents == "fole") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Fole);
        } else if (kind->contents == "fone") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Fone);
        } else if (kind->contents == "ford") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Ford);
        } else if (kind->contents == "fueq") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Fueq);
        } else if (kind->contents == "fugt") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Fugt);
        } else if (kind->contents == "fuge") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Fuge);
        } else if (kind->contents == "fult") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Fult);
        } else if (kind->contents == "fule") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Fule);
        } else if (kind->contents == "fune") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Fune);
        } else if (kind->contents == "funo") {
            return ParseBinSExpr(kind.TakeValue(), lparen.TakeValue(), BinaryOp::Funo);
        } else if (kind->contents == "addrof") {
            auto gv = ParseStrLit();
            CHECK_PARSE(gv);
            auto rparen = GetToken< Token::RParen >();
            CHECK_PARSE(rparen);

            return MakeExpr< AddrOf >(gv.TakeValue(), lparen.TakeValue(), rparen.TakeValue());
        }

        UNREACHABLE;
    }

    ParseResult< TypePtr > Parser::ParseType() {
        auto name
            = MaybeGetIdent({ "i8", "i16", "i32", "i64", "i128", "f32", "f64", "ptr", "void" });
        CHECK_PARSE(name);

        if (name->has_value()) {
            auto name_tok = *name.TakeValue();
            return MakeType< PrimitiveType >(std::string(name_tok.contents), name_tok);
        }

        auto lparen = PeekToken< Token::LParen >();
        if (lparen.Succeeded()) {
            return ParseTypeSExpr();
        }

        auto named_type = this->ParseExtIdentifer();
        CHECK_PARSE(named_type);
        auto [nm, tok] = named_type.TakeValue();
        return MakeType< PrimitiveType >(nm, tok);
    }

    namespace type_attrs
    {
        ATTR(SizeAttr, "size", IntLit)
        ATTR(TypeAttr, "type", Type)
    }; // namespace type_attrs

    ParseResult< TypePtr > Parser::ParseTypeSExpr() {
        using namespace type_attrs;

        auto lparen = GetToken< Token::LParen >();
        CHECK_PARSE(lparen);

        auto kind = GetIdent({
            "struct",
            "array",
            "vector",
        });
        CHECK_PARSE(kind);

        if (kind->contents == "struct") {
            std::vector< TypePtr > elems;
            while (true) {
                auto rparen = PeekToken();
                if (rparen->kind == Token::RParen) {
                    GetToken();
                    return MakeType< StructType >(std::move(elems), lparen.TakeValue(), *rparen);
                }

                auto elem = ParseType();
                CHECK_PARSE(elem);
                elems.push_back(elem.TakeValue());
            }
        } else if (kind->contents == "array") {
            auto attrs = ParseAttributes< SizeAttr, TypeAttr >();
            CHECK_PARSE(attrs);
            auto [size, type] = attrs.TakeValue();
            auto close        = GetToken< Token::RParen >();
            CHECK_PARSE(close);
            return MakeType< ArrayType >(
                std::move(size), std::move(type), lparen.TakeValue(), close.TakeValue());
        } else if (kind->contents == "vector") {
            auto attrs = ParseAttributes< SizeAttr, TypeAttr >();
            CHECK_PARSE(attrs);
            auto [size, type] = attrs.TakeValue();
            auto close        = GetToken< Token::RParen >();
            CHECK_PARSE(close);
            return MakeType< VectorType >(
                std::move(size), std::move(type), lparen.TakeValue(), close.TakeValue());
        }
        UNREACHABLE;
    }

    namespace loc_attrs
    {
        ATTR(NameAttr, "name", Identifier)
        ATTR(SizeAttr, "size", IntLit)
        ATTR(AddressAttr, "address", IntLit)
        ATTR(BaseAttr, "base", Identifier)
        ATTR(OffsetAttr, "offset", IntLit)
        ATTR(DispAttr, "displacement", IntLit)
        ATTR(IsExternalAttr, "is_external", BoolLit)
    }; // namespace loc_attrs

    ParseResult< Location > Parser::ParseRegisterLocationSExpr(Token lparen) {
        using namespace loc_attrs;
        auto attrs = ParseAttributes< NameAttr, SizeAttr >();
        CHECK_PARSE(attrs);
        auto [reg, size] = attrs.TakeValue();

        auto rparen = GetToken< Token::RParen >();
        CHECK_PARSE(rparen);

        return { { RegisterLocation(
            std::string(reg.contents), std::move(size), reg, lparen, rparen.TakeValue()) } };
    }

    ParseResult< Location > Parser::ParseMemoryLocationSExpr(Token lparen) {
        using namespace loc_attrs;
        auto attrs = ParseAttributes< AddressAttr, SizeAttr, DispAttr, IsExternalAttr >();
        CHECK_PARSE(attrs);
        auto [addr, size, disp, is_ext] = attrs.TakeValue();

        auto rparen = GetToken< Token::RParen >();
        CHECK_PARSE(rparen);

        return { { MemoryLocation(
            std::move(addr), std::move(size), std::move(disp), std::move(is_ext), lparen,
            rparen.TakeValue()) } };
    }

    ParseResult< Location > Parser::ParseIndirectMemoryLocationSExpr(Token lparen) {
        using namespace loc_attrs;
        auto attrs = ParseAttributes< BaseAttr, OffsetAttr, SizeAttr >();
        CHECK_PARSE(attrs);
        auto [base, offset, size] = attrs.TakeValue();

        auto rparen = GetToken< Token::RParen >();
        CHECK_PARSE(rparen);

        return { { IndirectMemoryLocation(
            std::string(base.contents), std::move(offset), std::move(size), lparen,
            rparen.TakeValue(), base) } };
    }

    ParseResult< Location > Parser::ParseLocationSExpr() {
        auto lparen = GetToken< Token::LParen >();
        CHECK_PARSE(lparen);

        auto kind = GetIdent({ "register", "memory", "memory_indirect" });
        CHECK_PARSE(kind);

        if (kind->contents == "register") {
            return ParseRegisterLocationSExpr(lparen.TakeValue());
        } else if (kind->contents == "memory") {
            return ParseMemoryLocationSExpr(lparen.TakeValue());
        } else {
            return ParseIndirectMemoryLocationSExpr(lparen.TakeValue());
        }
    }

    ParseResult< Location > Parser::ParseLocation() {
        auto tok = PeekToken< Token::LParen >();
        CHECK_PARSE(tok);

        if (tok->kind == Token::LParen) {
            return ParseLocationSExpr();
        }

        return (ERR << tok->GetPositionString() << ": Unexpected token `" << tok->contents
                    << "` while parsing a location")
            .str();
    }
} // namespace irene3::patchlang