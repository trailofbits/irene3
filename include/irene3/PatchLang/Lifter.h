#include <anvill/Result.h>
#include <exception>
#include <functional>
#include <irene3/PatchIR/PatchIROps.h>
#include <irene3/PatchLang/Expr.h>
#include <irene3/PatchLang/Exprs.h>
#include <irene3/PatchLang/Location.h>
#include <irene3/PatchLang/Stmt.h>
#include <irene3/PatchLang/Type.h>
#include <llvm/ADT/DenseMap.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/raw_ostream.h>
#include <mlir/Dialect/LLVMIR/LLVMDialect.h>
#include <mlir/IR/Attributes.h>
#include <mlir/IR/BuiltinOps.h>
#include <mlir/IR/Location.h>
#include <mlir/IR/MLIRContext.h>
#include <mlir/IR/Operation.h>
#include <mlir/IR/Types.h>
#include <mlir/IR/Value.h>
#include <string>
#include <unordered_map>
#include <vector>

namespace irene3::patchlang
{
    class UnhandledMLIRLift : public std::exception {
        std::optional< mlir::Location > loc;
        std::string message;

      public:
        UnhandledMLIRLift(std::optional< mlir::Location > loc, std::string message)
            : loc(loc) {
            llvm::raw_string_ostream ss(this->message);
            if (loc) {
                loc->print(ss);
            }

            ss << ": " << message;
        }

        const char *what() const noexcept override { return this->message.c_str(); }
    };

    class LifterContext {
      private:
        mlir::MLIRContext &mlir_cont;
        mlir::ModuleOp mod;

        uint64_t curr_value_indx;
        std::unordered_map< const void *, uint64_t > value_index;
        std::vector< std::string > value_names;
        llvm::DenseMap< mlir::Type, std::string > named_types;

        void LiftArgs(
            std::vector< patchlang::Stmt > &, patchir::CallOp cop, mlir::LLVM::LLVMFuncOp funcop);
        void LiftBody(mlir::LLVM::LLVMFuncOp funcop, std::vector< patchlang::Stmt > &);

        ExprPtr LiftValue(mlir::Value val);

        Stmt LiftOp(mlir::Operation &op);

        template< CastExprKind Kind, typename Op >
        ExprPtr LiftCastOp(Op op) {
            return MakeExpr< patchlang::CastExpr >(
                LiftType(op.getType()), this->GetRefExport(op.getOperand()), Kind, Token(),
                Token());
        }

        template< BinaryOp Kind, typename Op >
        ExprPtr LiftBinOp(Op op) {
            return MakeExpr< patchlang::BinaryExpr >(
                Kind, Token(), this->GetRefExport(op.getLhs()), this->GetRefExport(op.getRhs()),
                Token(), Token());
        }

        patchlang::TypePtr LiftType(mlir::Type ty);

        std::string GetValueName(mlir::Value val) {
            auto [it, inserted]
                = this->value_index.insert({ val.getAsOpaquePointer(), this->curr_value_indx });
            if (inserted) {
                this->value_names.emplace_back(std::to_string(this->curr_value_indx));
                return LifterContext::NameForIndex(this->curr_value_indx++);
            } else {
                return LifterContext::NameForIndex(it->second);
            }
        }

        std::string GetValueName(mlir::Value val, const std::string &name) {
            auto [it, inserted]
                = this->value_index.insert({ val.getAsOpaquePointer(), this->curr_value_indx });
            if (inserted) {
                this->value_names.emplace_back(std::to_string(this->curr_value_indx) + "_" + name);
                return LifterContext::NameForIndex(this->curr_value_indx++);
            } else {
                return LifterContext::NameForIndex(it->second);
            }
        }

      public:
        LifterContext(mlir::MLIRContext &mlir_cont, mlir::ModuleOp mod)
            : mlir_cont(mlir_cont)
            , mod(mod)
            , curr_value_indx(0) {}

        patchlang::IntLitExpr LowerBBCall(mlir::LLVM::CallOp cop);

        patchlang::IntLitExpr LowerOnlyControlFlowBlock(mlir::Block *block);

        patchlang::ExprPtr GetRefExport(mlir::Value op);

        void LowerTerminator(std::vector< patchlang::Stmt > &body, mlir::Operation *term);

        irene3::patchlang::Stmt LiftnonControlFlowOp(mlir::Operation &);

        irene3::patchlang::Region LiftRegion(irene3::patchir::RegionOp, bool);

        patchlang::TypeDecl AddNamedType(std::string s, mlir::Type ty);

        std::optional< patchlang::Location > LiftLoc(std::optional< mlir::Attribute > vop);

        Stmt LiftValueOp(patchir::ValueOp vop, mlir::Value representing);

        Stmt BindExprForMLIRValue(patchlang::ExprPtr expr, mlir::Value val);

        patchlang::External LiftExternal(patchir::FunctionOp);

        patchlang::ExternalGlobal LiftGlobal(patchir::Global);

        inline std::string NameForIndex(uint64_t ind) { return "named_val_" + value_names[ind]; }
    };

} // namespace irene3::patchlang