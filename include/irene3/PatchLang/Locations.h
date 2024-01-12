#pragma once
#include "Exprs.h"
#include "Location.h"

#include <anvill/Declarations.h>
#include <irene3/PatchLang/Expr.h>
#include <remill/Arch/Arch.h>
#include <string>
#include <variant>

namespace irene3::patchlang
{
    class RegisterLocation {
        std::string name;
        IntLitExpr size;
        Token name_token;
        Token first_tok;
        Token last_tok;

      public:
        RegisterLocation(
            std::string name, IntLitExpr&& size, Token name_token, Token first_tok, Token last_tok)
            : name(name)
            , size(std::move(size))
            , name_token(name_token)
            , first_tok(first_tok)
            , last_tok(last_tok) {}

        const IntLitExpr& GetSize() const { return size; }
        Token GetRegisterNameToken() const { return name_token; }
        std::string GetRegisterName() const { return name; }

        Token GetFirstToken() const { return first_tok; }
        Token GetLastToken() const { return last_tok; }
    };

    class MemoryLocation {
        IntLitExpr address;
        IntLitExpr size;
        IntLitExpr disp;
        BoolLitExpr is_external;
        Token first_tok;
        Token last_tok;

      public:
        MemoryLocation(
            IntLitExpr&& address,
            IntLitExpr&& size,
            IntLitExpr&& disp,
            BoolLitExpr&& is_external,
            Token first_tok,
            Token last_tok)
            : address(std::move(address))
            , size(std::move(size))
            , disp(disp)
            , is_external(is_external)
            , first_tok(first_tok)
            , last_tok(last_tok) {}

        const IntLitExpr& GetAddress() const { return address; }
        const IntLitExpr& GetSize() const { return size; }

        const IntLitExpr& GetDisp() const { return disp; }
        const BoolLitExpr& GetIsExternal() const { return is_external; }

        Token GetFirstToken() const { return first_tok; }
        Token GetLastToken() const { return last_tok; }
    };

    class IndirectMemoryLocation {
        std::string base;
        IntLitExpr offset;
        IntLitExpr size;
        Token base_tok;
        Token first_tok;
        Token last_tok;

      public:
        IndirectMemoryLocation(
            std::string base,
            IntLitExpr&& offset,
            IntLitExpr&& size,
            Token base_tok,
            Token first_tok,
            Token last_tok)
            : base(base)
            , offset(std::move(offset))
            , size(std::move(size))
            , base_tok(base_tok)
            , first_tok(first_tok)
            , last_tok(last_tok) {}

        Token GetBaseToken() const { return base_tok; }
        std::string GetBaseName() const { return base; }
        const IntLitExpr& GetOffset() const { return offset; }
        const IntLitExpr& GetSize() const { return size; }

        Token GetFirstToken() const { return first_tok; }
        Token GetLastToken() const { return last_tok; }
    };

    inline anvill::LowLoc ToAnvillLowLoc(const RegisterLocation& loc, const remill::Arch* arch) {
        return { arch->RegisterByName(loc.GetRegisterNameToken().contents), nullptr, 0,
                 loc.GetSize().GetValue().getExtValue() };
    }

    inline anvill::LowLoc ToAnvillLowLoc(const MemoryLocation& loc, const remill::Arch* arch) {
        return { nullptr, nullptr, loc.GetAddress().GetValue().getExtValue(),
                 loc.GetSize().GetValue().getExtValue() };
    }

    inline anvill::LowLoc ToAnvillLowLoc(
        const IndirectMemoryLocation& loc, const remill::Arch* arch) {
        return { nullptr, arch->RegisterByName(loc.GetBaseToken().contents),
                 loc.GetOffset().GetValue().getExtValue(), loc.GetSize().GetValue().getExtValue() };
    }

    inline anvill::LowLoc ToAnvillLowLoc(const Location& loc, const remill::Arch* arch) {
        return std::visit([arch](auto&& l) { return ToAnvillLowLoc(l, arch); }, loc);
    }
} // namespace irene3::patchlang