#include <irene3/PatchLang/Expr.h>
#include <irene3/PatchLang/Types.h>

namespace irene3::patchlang
{
    llvm::APSInt IntLitExpr::GetValue() const { return value; }
    LitBase IntLitExpr::GetBase() const { return base; }
    Token IntLitExpr::GetToken() const { return token; }
    Token IntLitExpr::GetFirstToken() const { return token; }
    Token IntLitExpr::GetLastToken() const { return token; }

    llvm::APFloat FloatLitExpr::GetValue() const { return value; }
    Token FloatLitExpr::GetToken() const { return token; }
    Token FloatLitExpr::GetFirstToken() const { return token; }
    Token FloatLitExpr::GetLastToken() const { return token; }

    Token BoolLitExpr::GetToken() const { return this->token; }
    bool BoolLitExpr::GetValue() const { return this->value; }
    Token BoolLitExpr::GetFirstToken() const { return token; }
    Token BoolLitExpr::GetLastToken() const { return token; }

    const std::string& StrLitExpr::GetValue() const { return value; }
    Token StrLitExpr::GetToken() const { return token; }
    Token StrLitExpr::GetFirstToken() const { return token; }
    Token StrLitExpr::GetLastToken() const { return token; }

    const Expr& SelectExpr::GetTrueCase() const { return *true_case; }
    const Expr& SelectExpr::GetFalseCase() const { return *false_case; }
    const Expr& SelectExpr::GetCondition() const { return *cond; }
    Token SelectExpr::GetFirstToken() const { return ftoken; }
    Token SelectExpr::GetLastToken() const { return ltoken; }

    Token DeclRefExpr::GetNameToken() const { return name_tok; }
    std::string DeclRefExpr::GetName() const { return std::string(name); }
    Token DeclRefExpr::GetFirstToken() const { return first_tok; }
    Token DeclRefExpr::GetLastToken() const { return last_tok; }

    Token BinaryExpr::GetOpToken() const { return op_tok; }
    BinaryOp BinaryExpr::GetOp() const { return op; }
    const Expr& BinaryExpr::GetLHS() const { return *lhs; }
    const Expr& BinaryExpr::GetRHS() const { return *rhs; }
    Token BinaryExpr::GetFirstToken() const { return first_tok; }
    Token BinaryExpr::GetLastToken() const { return last_tok; }

    Token UnaryExpr::GetOpToken() const { return op; }
    std::string UnaryExpr::GetOp() const { return std::string(op.contents); }
    const Expr& UnaryExpr::GetSub() const { return *sub; }
    Token UnaryExpr::GetFirstToken() const { return first_tok; }
    Token UnaryExpr::GetLastToken() const { return last_tok; }

    const Expr& GetElementPtrExpr::GetBase() const { return *base; }
    const Type& GetElementPtrExpr::ElementType() const { return *elem_ptr; }
    const std::vector< ExprPtr >& GetElementPtrExpr::GetIndices() const { return indices; }
    Token GetElementPtrExpr::GetFirstToken() const { return first_tok; }
    Token GetElementPtrExpr::GetLastToken() const { return last_tok; }

    const StrLitExpr& CallExpr::GetCallee() const { return callee; }
    const std::vector< ExprPtr >& CallExpr::GetArgs() const { return args; }
    Token CallExpr::GetFirstToken() const { return first_tok; }
    Token CallExpr::GetLastToken() const { return last_tok; }

    const StrLitExpr& CallIntrinsicExpr::GetCallee() const { return callee; }
    const std::vector< ExprPtr >& CallIntrinsicExpr::GetArgs() const { return args; }
    Token CallIntrinsicExpr::GetFirstToken() const { return first_tok; }
    Token CallIntrinsicExpr::GetLastToken() const { return last_tok; }

    const Expr& AllocaExpr::GetArraySize() const { return *arraySize; }
    const IntLitExpr& AllocaExpr::GetAlignment() const { return alignment; }
    const Type& AllocaExpr::GetType() const { return *type; }
    Token AllocaExpr::GetFirstToken() const { return first_tok; }
    Token AllocaExpr::GetLastToken() const { return last_tok; }

    const Expr& LoadExpr::GetPointer() const { return *ptr; }
    const Type& LoadExpr::GetType() const { return *type; }
    Token LoadExpr::GetFirstToken() const { return first_tok; }
    Token LoadExpr::GetLastToken() const { return last_tok; }

    Token NullExpr::GetFirstToken() const { return first_tok; }
    Token NullExpr::GetLastToken() const { return last_tok; }

    const Type& CastExpr::GetType() const { return *type; }
    const Expr& CastExpr::GetValue() const { return *value; }
    CastExprKind CastExpr::GetKind() const { return kind; }
    Token CastExpr::GetFirstToken() const { return first_tok; }
    Token CastExpr::GetLastToken() const { return last_tok; }

    const IntLitExpr& Splat::GetNumeElem() const { return this->num; }
    const Literal& Splat::GetValues() const { return *this->values; }
    const Type& Splat::GetElemType() const { return *this->elem_ptr; }

    const Literal& ConstantOp::GetValue() const { return *this->value; }
} // namespace irene3::patchlang