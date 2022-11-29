#include <clang/AST/AST.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/DeclGroup.h>
#include <clang/AST/Stmt.h>
#include <clang/Basic/Specifiers.h>
#include <clang/Frontend/ASTUnit.h>
#include <irene3/Codegen.h>
#include <llvm/IR/Constant.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Value.h>
#include <rellic/AST/DecompilationContext.h>
#include <rellic/AST/ExprCombine.h>
#include <rellic/AST/IRToASTVisitor.h>
#include <unordered_map>
#include <vector>

namespace irene3
{
    clang::CompoundStmt *Decompile(llvm::Function &function, clang::ASTUnit &ast_unit) {
        rellic::DecompilationContext dec_ctx(ast_unit);
        auto tu_decl = dec_ctx.ast_ctx.getTranslationUnitDecl();
        rellic::IRToASTVisitor ast_gen(dec_ctx);

        for (auto &func : function.getParent()->functions()) {
            // Inhibits the creation of temporary variables
            if (&func == &function) {
                continue;
            }
            ast_gen.VisitFunctionDecl(func);
        }

        std::vector< clang::Stmt * > stmts;
        for (auto &arg : function.args()) {
            auto ty        = dec_ctx.type_provider->GetArgumentType(arg);
            auto decl      = dec_ctx.ast.CreateVarDecl(tu_decl, ty, arg.getName().str());
            auto decl_stmt = dec_ctx.ast.CreateDeclStmt(decl);
            stmts.push_back(decl_stmt);
            dec_ctx.value_decls[&arg] = decl;
        }

        ast_gen.VisitBasicBlock(function.getEntryBlock(), stmts);

        auto stmt = clang::CompoundStmt::Create(dec_ctx.ast_ctx, stmts, {}, {});

        rellic::ExprCombine ec(dec_ctx);
        ec.VisitStmt(stmt);
        return stmt;
    }
} // namespace irene3