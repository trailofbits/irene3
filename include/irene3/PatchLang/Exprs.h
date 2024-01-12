#pragma once

#include <irene3/PatchLang/Expr.h>
#include <irene3/PatchLang/Lexer.h>
#include <irene3/PatchLang/Type.h>
#include <llvm/ADT/APSInt.h>
#include <string>

namespace irene3::patchlang
{
    template< typename TExpr, typename... Ts >
    ExprPtr MakeExpr(Ts&&... ts) {
        return std::make_unique< Expr >(TExpr(std::forward< Ts >(ts)...));
    }

    enum class LitBase
    {
        Decimal,
        Hexadecimal,
        Octal,
        Binary
    };

    class BoolLitExpr {
        bool value;
        Token token;

      public:
        BoolLitExpr(bool value, Token tok)
            : value(value)
            , token(tok) {}

        Token GetToken() const;
        bool GetValue() const;

        Token GetFirstToken() const;
        Token GetLastToken() const;
    };

    class IntLitExpr {
        llvm::APSInt value;
        LitBase base;
        Token token;

      public:
        using enum LitBase;

        IntLitExpr(llvm::APSInt value, LitBase base, Token tok)
            : value(value)
            , base(base)
            , token(tok) {}

        llvm::APSInt GetValue() const;
        LitBase GetBase() const;
        Token GetToken() const;

        Token GetFirstToken() const;
        Token GetLastToken() const;

        inline explicit operator uint64_t() const { return value.getZExtValue(); }

        inline explicit operator int64_t() const { return value.getSExtValue(); }
    };

    class SelectExpr {
        ExprPtr cond;
        ExprPtr true_case;
        ExprPtr false_case;
        Token ftoken;
        Token ltoken;

      public:
        using enum LitBase;

        SelectExpr(ExprPtr cond, ExprPtr true_case, ExprPtr false_case, Token ftoken, Token ltoken)
            : cond(std::move(cond))
            , true_case(std::move(true_case))
            , false_case(std::move(false_case))
            , ftoken(ftoken)
            , ltoken(ltoken) {}

        const Expr& GetTrueCase() const;
        const Expr& GetFalseCase() const;
        const Expr& GetCondition() const;

        Token GetFirstToken() const;
        Token GetLastToken() const;
    };

    class StrLitExpr {
        std::string value;
        Token token;

      public:
        StrLitExpr(std::string value, Token tok)
            : value(value)
            , token(tok) {}

        const std::string& GetValue() const;
        Token GetToken() const;

        Token GetFirstToken() const;
        Token GetLastToken() const;
    };

    class AddrOf {
        StrLitExpr global_val;
        Token ftoken;
        Token ltoken;

      public:
        AddrOf(StrLitExpr global_val, Token ftoken, Token ltoken)
            : global_val(std::move(global_val))
            , ftoken(ftoken)
            , ltoken(ltoken) {}

        const StrLitExpr& GetGValue() const { return this->global_val; }
        Token GetFirstToken() const { return ftoken; }
        Token GetLastToken() const { return ltoken; }
    };

    class DeclRefExpr {
        std::string name;
        Token name_tok;
        Token first_tok;
        Token last_tok;

      public:
        DeclRefExpr(std::string name, Token name_tok, Token first_tok, Token last_tok)
            : name(name)
            , name_tok(name_tok)
            , first_tok(first_tok)
            , last_tok(last_tok) {}

        Token GetNameToken() const;
        std::string GetName() const;

        Token GetFirstToken() const;
        Token GetLastToken() const;
    };

    constexpr unsigned Nuw     = 1 << 31;
    constexpr unsigned Nsw     = 1 << 30;
    constexpr unsigned OP_MASK = 0x00FFFFFF;

    enum BinaryOp : unsigned
    {
        Add,
        Fadd,
        Sub,
        Fsub,
        Mul,
        Fmul,
        Udiv,
        Sdiv,
        Fdiv,
        Srem,
        Frem,
        Shl,
        Lshr,
        Ashr,
        And,
        Or,
        Xor,

        Eq,
        Ne,
        Ugt,
        Uge,
        Ult,
        Ule,
        Sgt,
        Sge,
        Slt,
        Sle,

        AddNuw    = Add | Nuw,
        AddNsw    = Add | Nsw,
        AddNuwNsw = Add | Nuw | Nsw,

        SubNuw    = Sub | Nuw,
        SubNsw    = Sub | Nsw,
        SubNuwNsw = Sub | Nuw | Nsw,

        MulNuw    = Mul | Nuw,
        MulNsw    = Mul | Nsw,
        MulNuwNsw = Mul | Nuw | Nsw,

        ShlNuw    = Shl | Nuw,
        ShlNsw    = Shl | Nsw,
        ShlNuwNsw = Shl | Nuw | Nsw,
    };

    class BinaryExpr {
        BinaryOp op;
        Token op_tok;
        ExprPtr lhs;
        ExprPtr rhs;
        Token first_tok;
        Token last_tok;

      public:
        BinaryExpr(
            BinaryOp op, Token op_tok, ExprPtr lhs, ExprPtr rhs, Token first_tok, Token last_tok)
            : op(op)
            , op_tok(op_tok)
            , lhs(std::move(lhs))
            , rhs(std::move(rhs))
            , first_tok(first_tok)
            , last_tok(last_tok) {}

        BinaryOp GetOp() const;
        Token GetOpToken() const;
        const Expr& GetLHS() const;
        const Expr& GetRHS() const;

        Token GetFirstToken() const;
        Token GetLastToken() const;
    };

    class UnaryExpr {
        Token op;
        ExprPtr sub;
        Token first_tok;
        Token last_tok;

      public:
        UnaryExpr(Token op, ExprPtr sub, Token first_tok, Token last_tok)
            : op(op)
            , sub(std::move(sub))
            , first_tok(first_tok)
            , last_tok(last_tok) {}

        Token GetOpToken() const;
        std::string GetOp() const;
        const Expr& GetSub() const;

        Token GetFirstToken() const;
        Token GetLastToken() const;
    };

    class GetElementPtrExpr {
        ExprPtr base;
        TypePtr elem_ptr;
        std::vector< ExprPtr > indices;
        Token first_tok;
        Token last_tok;

      public:
        GetElementPtrExpr(
            ExprPtr base,
            TypePtr elem_ptr,
            std::vector< ExprPtr >&& indices,
            Token first_tok,
            Token last_tok)
            : base(std::move(base))
            , elem_ptr(std::move(elem_ptr))
            , indices(std::move(indices))
            , first_tok(first_tok)
            , last_tok(last_tok) {}

        const Expr& GetBase() const;
        const Type& ElementType() const;
        const std::vector< ExprPtr >& GetIndices() const;

        Token GetFirstToken() const;
        Token GetLastToken() const;
    };

    class CallExpr {
        StrLitExpr callee;
        std::vector< ExprPtr > args;
        Token first_tok;
        Token last_tok;

      public:
        CallExpr(
            StrLitExpr&& callee, std::vector< ExprPtr >&& args, Token first_tok, Token last_tok)
            : callee(std::move(callee))
            , args(std::move(args))
            , first_tok(first_tok)
            , last_tok(last_tok) {}

        const StrLitExpr& GetCallee() const;
        const std::vector< ExprPtr >& GetArgs() const;

        Token GetFirstToken() const;
        Token GetLastToken() const;
    };

    class AllocaExpr {
        ExprPtr arraySize;
        IntLitExpr alignment;
        TypePtr type;
        Token first_tok;
        Token last_tok;

      public:
        AllocaExpr(
            ExprPtr arraySize,
            IntLitExpr&& alignment,
            TypePtr type,
            Token first_tok,
            Token last_tok)
            : arraySize(std::move(arraySize))
            , alignment(std::move(alignment))
            , type(std::move(type))
            , first_tok(first_tok)
            , last_tok(last_tok) {}

        const Expr& GetArraySize() const;
        const IntLitExpr& GetAlignment() const;
        const Type& GetType() const;

        Token GetFirstToken() const;
        Token GetLastToken() const;
    };

    class LoadExpr {
        TypePtr type;
        bool is_volatile;
        ExprPtr ptr;
        Token first_tok;
        Token last_tok;

      public:
        LoadExpr(TypePtr type, bool is_volatile, ExprPtr ptr, Token first_tok, Token last_tok)
            : type(std::move(type))
            , is_volatile(is_volatile)
            , ptr(std::move(ptr))
            , first_tok(first_tok)
            , last_tok(last_tok) {}

        const Expr& GetPointer() const;
        const Type& GetType() const;
        const bool& GetIsVolatile() const { return this->is_volatile; }

        Token GetFirstToken() const;
        Token GetLastToken() const;
    };

    class NullExpr {
        Token first_tok;
        Token last_tok;

      public:
        NullExpr(Token first_tok, Token last_tok)
            : first_tok(first_tok)
            , last_tok(last_tok) {}

        Token GetFirstToken() const;
        Token GetLastToken() const;
    };

    enum class CastExprKind
    {
        Trunc,
        ZExt,
        SExt,
        FPTrunc,
        FPExt,
        FPToUI,
        FPToSI,
        UIToFP,
        SIToFP,
        PtrToInt,
        IntToPtr,
        BitCast,
    };

    class CastExpr {
        TypePtr type;
        ExprPtr value;
        CastExprKind kind;
        Token first_tok;
        Token last_tok;

      public:
        using enum CastExprKind;

        CastExpr(TypePtr type, ExprPtr value, CastExprKind kind, Token first_tok, Token last_tok)
            : type(std::move(type))
            , value(std::move(value))
            , kind(kind)
            , first_tok(first_tok)
            , last_tok(last_tok) {}

        const Type& GetType() const;
        const Expr& GetValue() const;
        CastExprKind GetKind() const;
        Token GetFirstToken() const;
        Token GetLastToken() const;
    };
} // namespace irene3::patchlang