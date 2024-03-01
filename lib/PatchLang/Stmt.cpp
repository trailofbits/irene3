#include <irene3/PatchLang/Stmt.h>
namespace irene3::patchlang
{
    const Expr& WhileStmt::GetCond() const { return *this->cond; }
    const std::vector< Stmt >& WhileStmt::GetThen() const { return this->then; }
    WhileStmt::WhileStmt(
        ExprPtr&& cond, std::vector< Stmt >&& then, Token first_tok, Token last_tok)
        : cond(std::move(cond))
        , then(std::move(then))
        , first_tok(first_tok)
        , last_tok(last_tok) {}

    const Expr& IfStmt::GetCond() const { return *this->cond; }
    const std::vector< Stmt >& IfStmt::GetThen() const { return this->then; }
    const std::vector< Stmt >& IfStmt::GetElse() const { return this->elsestmt; }
    IfStmt::IfStmt(
        ExprPtr&& cond,
        std::vector< Stmt >&& then,
        std::vector< Stmt >&& elseb,
        Token first_tok,
        Token last_tok)
        : cond(std::move(cond))
        , then(std::move(then))
        , elsestmt(std::move(elseb))
        , first_tok(first_tok)
        , last_tok(last_tok) {}
} // namespace irene3::patchlang