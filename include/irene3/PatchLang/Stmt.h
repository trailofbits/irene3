#pragma once

#include "Expr.h"
#include "Exprs.h"
#include "Locations.h"
#include "Type.h"
#include "Types.h"
#include "irene3/Util.h"

#include <anvill/Declarations.h>
#include <anvill/Type.h>
#include <llvm/ADT/APSInt.h>
#include <memory>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace irene3::patchlang
{
    class LetDeclStmt;
    class StoreStmt;
    class ReturnStmt;
    class ExprStmt;
    class ValueStmt;
    class GotoStmt;
    class NopStmt;
    class ConditionalGotoStmt;
    class FailedToLiftStmt;
    class IfStmt;
    class WhileStmt;

    using Stmt = std::variant<
        LetDeclStmt,
        StoreStmt,
        ReturnStmt,
        ExprStmt,
        ValueStmt,
        GotoStmt,
        ConditionalGotoStmt,
        NopStmt,
        FailedToLiftStmt,
        IfStmt,
        WhileStmt >;
    using StmtPtr = std::unique_ptr< Stmt >;
    template< typename T >
    concept IsStmt = std::is_same_v< std::remove_cv_t< T >, Stmt >;

    template< typename TStmt, typename... Ts >
    StmtPtr MakeStmt(Ts&&... ts) {
        return std::make_unique< Stmt >(TStmt(std::forward< Ts >(ts)...));
    }

    class FailedToLiftStmt {
        StrLitExpr message;
        Token first_tok;
        Token last_tok;

      public:
        FailedToLiftStmt(StrLitExpr&& message, Token first_tok, Token last_tok)
            : message(std::move(message))
            , first_tok(first_tok)
            , last_tok(last_tok) {}

        const StrLitExpr& GetMessage() const { return message; }
        Token GetFirstToken() const { return first_tok; }
        Token GetLastToken() const { return last_tok; }
    };

    class IfStmt {
        ExprPtr cond;
        std::vector< Stmt > then;
        std::vector< Stmt > elsestmt;
        Token first_tok;
        Token last_tok;

      public:
        IfStmt(
            ExprPtr&& cond,
            std::vector< Stmt >&& then,
            std::vector< Stmt >&& elsestmt,
            Token first_tok,
            Token last_tok);

        const Expr& GetCond() const;
        const std::vector< Stmt >& GetThen() const;
        const std::vector< Stmt >& GetElse() const;
        Token GetFirstToken() const { return first_tok; }
        Token GetLastToken() const { return last_tok; }
    };

    class WhileStmt {
        ExprPtr cond;
        std::vector< Stmt > then;
        Token first_tok;
        Token last_tok;

      public:
        WhileStmt(ExprPtr&& cond, std::vector< Stmt >&& then, Token first_tok, Token last_tok);

        const Expr& GetCond() const;
        const std::vector< Stmt >& GetThen() const;
        Token GetFirstToken() const { return first_tok; }
        Token GetLastToken() const { return last_tok; }
    };

    class LetDeclStmt {
        std::string name;
        ExprPtr expr;
        Token first_tok;
        Token last_tok;

      public:
        LetDeclStmt(const std::string& name, ExprPtr&& expr, Token first_tok, Token last_tok)
            : name(name)
            , expr(std::move(expr))
            , first_tok(first_tok)
            , last_tok(last_tok) {}

        const std::string& GetName() const { return name; }
        const Expr& GetExpr() const { return *expr; }
        Token GetFirstToken() const { return first_tok; }
        Token GetLastToken() const { return last_tok; }
    };

    class StoreStmt {
        ExprPtr value;
        ExprPtr dest;
        bool is_volatile;
        Token first_tok;
        Token last_tok;

      public:
        StoreStmt(
            ExprPtr&& value, ExprPtr&& dest, bool is_volatile, Token first_tok, Token last_tok)
            : value(std::move(value))
            , dest(std::move(dest))
            , is_volatile(is_volatile)
            , first_tok(first_tok)
            , last_tok(last_tok) {}

        const Expr& GetValue() const { return *value; }
        const Expr& GetDestination() const { return *dest; }
        bool GetIsVolatile() const { return this->is_volatile; }
        Token GetFirstToken() const { return first_tok; }
        Token GetLastToken() const { return last_tok; }
    };

    class ReturnStmt {
        std::optional< Expr > value;
        Token first_tok;
        Token last_tok;

      public:
        ReturnStmt(Expr&& value, Token first_tok, Token last_tok)
            : value(std::move(value))
            , first_tok(first_tok)
            , last_tok(last_tok) {}
        ReturnStmt(Token first_tok, Token last_tok)
            : value(std::nullopt)
            , first_tok(first_tok)
            , last_tok(last_tok) {}

        std::optional< std::reference_wrapper< const Expr > > GetValue() const {
            if (value) {
                return std::cref(*value);
            } else {
                return std::nullopt;
            }
        }
        Token GetFirstToken() const { return first_tok; }
        Token GetLastToken() const { return last_tok; }
    };

    class ExprStmt {
        ExprPtr expr;
        Token first_tok;
        Token last_tok;

      public:
        // TODO(Ian): we dont really need to store tokens twice
        ExprStmt(ExprPtr&& expr, Token first_tok, Token last_tok)
            : expr(std::move(expr))
            , first_tok(first_tok)
            , last_tok(last_tok) {}
        const Expr& GetExpr() const { return *expr; }

        Token GetFirstToken() const { return first_tok; }
        Token GetLastToken() const { return last_tok; }
    };

    class ValueStmt {
        std::string name;
        std::optional< Location > at_entry;
        std::optional< Location > at_exit;
        TypePtr value_type;
        Token name_tok;
        Token first_tok;
        Token last_tok;

      public:
        ValueStmt(
            std::string name,
            std::optional< Location >&& at_entry,
            std::optional< Location >&& at_exit,
            TypePtr value_type,
            Token name_tok,
            Token first_tok,
            Token last_tok)
            : name(name)
            , at_entry(std::move(at_entry))
            , at_exit(std::move(at_exit))
            , value_type(std::move(value_type))
            , name_tok(name_tok)
            , first_tok(first_tok)
            , last_tok(last_tok) {}

        const std::string GetName() const { return name; }
        Token GetNameToken() const { return name_tok; }
        const std::optional< Location >& GetLocationAtEntry() const { return at_entry; }
        const std::optional< Location >& GetLocationAtExit() const { return at_exit; }
        const Type& GetValueType() const { return *value_type; }

        Token GetFirstToken() const { return first_tok; }
        Token GetLastToken() const { return last_tok; }
    };

    class ConditionalGotoStmt {
        IntLitExpr addr;
        ExprPtr cond;
        Token first_tok;
        Token last_tok;

      public:
        ConditionalGotoStmt(IntLitExpr&& addr, ExprPtr&& cond, Token first_tok, Token last_tok)
            : addr(addr)
            , cond(std::move(cond))
            , first_tok(first_tok)
            , last_tok(last_tok) {}

        const IntLitExpr& GetTarget() const { return this->addr; }
        const Expr& GetCond() const { return *this->cond; }
        Token GetFirstToken() const { return first_tok; }
        Token GetLastToken() const { return last_tok; }
    };

    class GotoStmt {
        IntLitExpr addr;
        Token first_tok;
        Token last_tok;

      public:
        GotoStmt(IntLitExpr&& addr, Token first_tok, Token last_tok)
            : addr(addr)
            , first_tok(first_tok)
            , last_tok(last_tok) {}

        const IntLitExpr& GetTarget() const { return this->addr; }
        Token GetFirstToken() const { return first_tok; }
        Token GetLastToken() const { return last_tok; }
    };

    class NopStmt {
        Token first_tok;
        Token last_tok;

      public:
        NopStmt(Token first_tok, Token last_tok)
            : first_tok(first_tok)
            , last_tok(last_tok) {}

        Token GetFirstToken() const { return first_tok; }
        Token GetLastToken() const { return last_tok; }
    };

    class StackOffset {
        RegisterLocation loc;
        IntLitExpr offset;
        Token first_tok;
        Token last_tok;

      public:
        StackOffset(RegisterLocation loc, IntLitExpr&& offset, Token first_tok, Token last_tok)
            : loc(loc)
            , offset(offset)
            , first_tok(first_tok)
            , last_tok(last_tok) {}

        const IntLitExpr& GetOffset() const { return this->offset; }
        const RegisterLocation& GetRegLoc() const { return this->loc; }
        Token GetFirstToken() const { return first_tok; }
        Token GetLastToken() const { return last_tok; }
    };

    class Region {
        std::vector< Stmt > body;
        IntLitExpr addr;
        IntLitExpr size;
        IntLitExpr stack_offset_entry;
        IntLitExpr stack_offset_exit;
        IntLitExpr region_uid;
        std::vector< StackOffset > stack_offsets_entry;
        std::vector< StackOffset > stack_offsets_exit;
        Token first_tok;
        Token last_tok;

      public:
        Region(
            std::vector< Stmt >&& body,
            IntLitExpr&& addr,
            IntLitExpr&& size,
            IntLitExpr&& stack_offset_entry,
            IntLitExpr&& stack_offset_exit,
            IntLitExpr&& region_uid,
            std::vector< StackOffset >&& stack_offsets_entry,
            std::vector< StackOffset >&& stack_offsets_exit,
            Token first_tok,
            Token last_tok)
            : body(std::move(body))
            , addr(std::move(addr))
            , size(std::move(size))
            , stack_offset_entry(std::move(stack_offset_entry))
            , stack_offset_exit(std::move(stack_offset_exit))
            , region_uid(region_uid)
            , stack_offsets_entry(stack_offsets_entry)
            , stack_offsets_exit(stack_offsets_exit)
            , first_tok(first_tok)
            , last_tok(last_tok) {}

        Region(Region&& other)
            : body(std::move(other.body))
            , addr(std::move(other.addr))
            , size(std::move(other.size))
            , stack_offset_entry(std::move(other.stack_offset_entry))
            , stack_offset_exit(std::move(other.stack_offset_exit))
            , region_uid(std::move(other.region_uid))
            , stack_offsets_entry(std::move(other.stack_offsets_entry))
            , stack_offsets_exit(std::move(other.stack_offsets_exit))
            , first_tok(other.first_tok)
            , last_tok(other.last_tok) {}

        Region& operator=(Region&& other) {
            body               = std::move(other.body);
            addr               = std::move(other.addr);
            size               = std::move(other.size);
            stack_offset_entry = std::move(other.stack_offset_entry);
            stack_offset_exit  = std::move(other.stack_offset_exit);
            return *this;
        }

        const std::vector< Stmt >& GetBody() const { return body; }
        std::vector< Stmt >& GetMutableBody() { return body; }
        const IntLitExpr& GetAddress() const { return addr; }
        const IntLitExpr& GetUID() const { return region_uid; }
        const IntLitExpr& GetSize() const { return size; }
        const IntLitExpr& GetStackOffsetAtEntry() const { return stack_offset_entry; }
        const IntLitExpr& GetStackOffsetAtExit() const { return stack_offset_exit; }
        const std::vector< StackOffset >& GetExitRegOffsets() const { return stack_offsets_exit; }
        const std::vector< StackOffset >& GetEntryRegOffsets() const { return stack_offsets_entry; }

        Token GetFirstToken() const { return first_tok; }
        Token GetLastToken() const { return last_tok; }
    };

    class Function {
        std::vector< Region > regions;
        IntLitExpr address;
        IntLitExpr disp;
        BoolLitExpr is_external;
        std::string name;
        Token name_tok;
        Token first_tok;
        Token last_tok;

      public:
        Function(
            std::vector< Region >&& regions,
            IntLitExpr&& address,
            IntLitExpr&& disp,
            BoolLitExpr&& is_external,
            std::string name,
            Token name_tok,
            Token first_tok,
            Token last_tok)
            : regions(std::move(regions))
            , address(std::move(address))
            , disp(disp)
            , is_external(is_external)
            , name(name)
            , name_tok(name_tok)
            , first_tok(first_tok)
            , last_tok(last_tok) {}
        Function(Function&& other)
            : regions(std::move(other.regions))
            , address(std::move(other.address))
            , disp(std::move(other.disp))
            , is_external(std::move(other.is_external))
            , name(other.name)
            , first_tok(other.first_tok)
            , last_tok(other.last_tok) {}

        Function& operator=(Function&& other) {
            regions = std::move(other.regions);
            address = std::move(other.address);
            name    = other.name;

            return *this;
        }

        const std::vector< Region >& GetRegions() const { return regions; }
        std::vector< Region >& GetMutableRegions() { return regions; }
        const IntLitExpr& GetAddress() const { return address; }
        const IntLitExpr& GetDisp() const { return disp; }
        const BoolLitExpr& GetIsExternal() const { return is_external; }

        Token GetNameToken() const { return name_tok; }
        std::string GetName() const { return std::string(name); }

        Token GetFirstToken() const { return first_tok; }
        Token GetLastToken() const { return last_tok; }
    };

    class External {
      private:
        IntLitExpr address;
        IntLitExpr disp;
        BoolLitExpr is_external;
        std::string name;
        TypePtr retty;
        std::vector< TypePtr > oprange;
        Token name_tok;
        Token first_tok;
        Token last_tok;

      public:
        External(
            IntLitExpr&& address,
            IntLitExpr&& disp,
            BoolLitExpr&& is_external,
            std::string name,
            TypePtr&& retty,
            std::vector< TypePtr >&& oprange,
            Token name_tok,
            Token first_tok,
            Token last_tok)
            : address(address)
            , disp(disp)
            , is_external(is_external)
            , name(name)
            , retty(std::move(retty))
            , oprange(std::move(oprange))
            , name_tok(name_tok)
            , first_tok(first_tok)
            , last_tok(last_tok) {}

        const IntLitExpr& GetAddress() const { return address; }
        const IntLitExpr& GetDisp() const { return disp; }
        const BoolLitExpr& GetIsExternal() const { return is_external; }

        Token GetNameToken() const { return name_tok; }
        std::string GetName() const { return std::string(name); }

        Token GetFirstToken() const { return first_tok; }
        Token GetLastToken() const { return last_tok; }

        const std::vector< TypePtr >& GetArgs() const { return this->oprange; }

        const Type& GetRetTy() const { return *this->retty; }
    };

    class ExternalGlobal {
        IntLitExpr address;
        IntLitExpr disp;
        BoolLitExpr is_external;
        IntLitExpr bit_size;
        std::string name;
        TypePtr gv_ty;
        Token name_tok;
        Token first_tok;
        Token last_tok;

      public:
        ExternalGlobal(
            IntLitExpr&& address,
            IntLitExpr&& disp,
            BoolLitExpr&& is_external,
            IntLitExpr&& bit_size,
            std::string name,
            TypePtr&& gv_ty,
            Token name_tok,
            Token first_tok,
            Token last_tok)
            : address(address)
            , disp(disp)
            , is_external(is_external)
            , bit_size(bit_size)
            , name(name)
            , gv_ty(std::move(gv_ty))
            , name_tok(name_tok)
            , first_tok(first_tok)
            , last_tok(last_tok) {}

        const IntLitExpr& GetAddress() const { return address; }
        const IntLitExpr& GetDisp() const { return disp; }
        const BoolLitExpr& GetIsExternal() const { return is_external; }
        const IntLitExpr& GetBitSize() const { return this->bit_size; }

        Token GetNameToken() const { return name_tok; }
        std::string GetName() const { return std::string(name); }

        Token GetFirstToken() const { return first_tok; }
        Token GetLastToken() const { return last_tok; }
        const Type& GetTy() const { return *this->gv_ty; }
    };

    class TypeDecl {
        std::string name;
        TypePtr defined_type;
        Token name_tok;
        Token first_tok;
        Token last_tok;

      public:
        TypeDecl(
            std::string name,
            TypePtr&& defined_type,
            Token name_tok,
            Token first_tok,
            Token last_tok)
            : name(name)
            , defined_type(std::move(defined_type))
            , name_tok(name_tok)
            , first_tok(first_tok)
            , last_tok(last_tok) {}

        Token GetNameToken() const { return name_tok; }
        std::string GetName() const { return std::string(name); }

        Token GetFirstToken() const { return first_tok; }
        Token GetLastToken() const { return last_tok; }
        const Type& GetTy() const { return *this->defined_type; }
    };

    using LangDecl = std::variant< Function, External, ExternalGlobal, TypeDecl >;

    class PModule {
      private:
        StrLitExpr datalayout;
        StrLitExpr target_triple;
        IntLitExpr image_base;
        std::vector< LangDecl > decls;
        Token first_tok;
        Token last_tok;

      public:
        PModule(
            StrLitExpr datalayout,
            StrLitExpr target_triple,
            IntLitExpr image_base,
            std::vector< LangDecl > decls,
            Token first_tok,
            Token last_tok)
            : datalayout(std::move(datalayout))
            , target_triple(std::move(target_triple))
            , image_base(std::move(image_base))
            , decls(std::move(decls))
            , first_tok(std::move(first_tok))
            , last_tok(std::move(last_tok)) {}

        const StrLitExpr& GetDataLayout() const { return datalayout; }
        const StrLitExpr& GetTargetTriple() const { return target_triple; }
        const IntLitExpr& GetImageBase() const { return this->image_base; }
        const std::vector< LangDecl >& GetDecls() const { return decls; }
        std::vector< LangDecl >& GetMutableDecls() { return decls; }
        Token GetFirstToken() const { return first_tok; }
        Token GetLastToken() const { return last_tok; }
    };
} // namespace irene3::patchlang
