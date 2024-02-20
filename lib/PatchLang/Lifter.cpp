#include "irene3/PatchLang/Locations.h"

#include <anvill/ABI.h>
#include <anvill/Result.h>
#include <functional>
#include <glog/logging.h>
#include <irene3/PatchIR/PatchIRAttrs.h>
#include <irene3/PatchIR/PatchIROps.h>
#include <irene3/PatchLang/Expr.h>
#include <irene3/PatchLang/Exprs.h>
#include <irene3/PatchLang/Lexer.h>
#include <irene3/PatchLang/Lifter.h>
#include <irene3/PatchLang/Location.h>
#include <irene3/PatchLang/Stmt.h>
#include <irene3/PatchLang/Type.h>
#include <irene3/PatchLang/Types.h>
#include <irene3/Util.h>
#include <llvm/ADT/APSInt.h>
#include <llvm/ADT/TypeSwitch.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/Printable.h>
#include <llvm/Support/raw_ostream.h>
#include <memory>
#include <mlir/Dialect/LLVMIR/LLVMDialect.h>
#include <mlir/Dialect/LLVMIR/LLVMTypes.h>
#include <mlir/IR/Attributes.h>
#include <mlir/IR/BlockSupport.h>
#include <mlir/IR/BuiltinAttributes.h>
#include <mlir/IR/BuiltinOps.h>
#include <mlir/IR/BuiltinTypes.h>
#include <mlir/IR/Location.h>
#include <mlir/IR/MLIRContext.h>
#include <mlir/IR/Operation.h>
#include <mlir/IR/SymbolTable.h>
#include <mlir/IR/Value.h>
#include <mlir/Support/LLVM.h>
#include <optional>
#include <sstream>
#include <string>
#include <variant>
#include <vector>

namespace irene3::patchlang
{
    namespace
    {
        llvm::APSInt APSIntFromUnsigned(uint64_t un) { return llvm::APSInt::getUnsigned(un); }
        llvm::APSInt APSIntFromSigned(int64_t i) { return llvm::APSInt::get(i); }

        IntLitExpr IntLitExp(llvm::APSInt i) { return IntLitExpr(i, LitBase::Decimal, Token()); }
        ExprPtr IntLit(llvm::APSInt i) { return std::make_unique< Expr >(IntLitExp(i)); }
        ExprPtr FloatLit(llvm::APFloat f) {
            return std::make_unique< Expr >(FloatLitExpr(f, Token{}));
        };
        ExprPtr BoolLit(bool val) { return std::make_unique< Expr >(BoolLitExpr(val, Token{})); }
        template< typename T >
        concept Printable = requires(T a, llvm::raw_ostream& os) { a.print(os); };

        template< Printable T >
        std::string MLIRThingToString(T&& it) {
            std::string s;
            llvm::raw_string_ostream ss(s);
            it.print(ss);
            return s;
        }

    } // namespace

    patchlang::TypePtr LifterContext::LiftType(mlir::Type ty) {
        if (this->named_types.find(ty) != this->named_types.end()) {
            return MakeType< PrimitiveType >(this->named_types.at(ty), Token());
        }
        return llvm::TypeSwitch< mlir::Type, TypePtr >(ty)
            .Case< mlir::LLVM::LLVMArrayType >([&](mlir::LLVM::LLVMArrayType arr) {
                auto iexpr = IntLitExp(APSIntFromUnsigned(arr.getNumElements()));
                auto res   = this->LiftType(arr.getElementType());
                return MakeType< ArrayType >(std::move(iexpr), std::move(res), Token(), Token());
            })
            .Case< mlir::IntegerType >([&](mlir::IntegerType inty) {
                return MakeType< PrimitiveType >("i" + std::to_string(inty.getWidth()), Token());
            })
            .Case< mlir::FloatType >([&](mlir::FloatType fty) {
                return MakeType< PrimitiveType >("f" + std::to_string(fty.getWidth()), Token());
            })
            .Case< mlir::LLVM::LLVMPointerType >([&](mlir::LLVM::LLVMPointerType pty) {
                return MakeType< PrimitiveType >("ptr", Token());
            })
            .Case< mlir::LLVM::LLVMVoidType >(
                [&](auto pty) { return MakeType< PrimitiveType >("void", Token()); })
            .Case< mlir::LLVM::LLVMStructType >([&](mlir::LLVM::LLVMStructType sty) {
                std::vector< TypePtr > elems;

                for (auto ty : sty.getBody()) {
                    elems.push_back(LiftType(ty));
                }

                return MakeType< StructType >(std::move(elems), Token(), Token());
            })
            .Default([&](auto v) -> TypePtr {
                throw patchlang::UnhandledMLIRLift(
                    std::nullopt, "Unhandled ty: " + MLIRThingToString(ty));
            });
    }

    ExprPtr LifterContext::LiftValue(mlir::Value val) {
        auto op_ptr = val.getDefiningOp();
        if (!op_ptr) {
            throw UnhandledMLIRLift(
                val.getLoc(), "Unsupported value type " + MLIRThingToString(val));
        }
        auto& op = *op_ptr;

        return llvm::TypeSwitch< mlir::Operation&, patchlang::ExprPtr >(op)
            .Case< mlir::LLVM::AddressOfOp >([&](mlir::LLVM::AddressOfOp op) {
                return MakeExpr< AddrOf >(
                    StrLitExpr(op.getGlobalName().str(), Token()), Token(), Token());
            })
            .Case< mlir::LLVM::AllocaOp >([&](mlir::LLVM::AllocaOp op) {
                auto elem  = this->LiftType(*op.getElemType());
                auto aling = *op.getAlignment();
                auto ref   = this->GetRefExport(op.getArraySize());
                return MakeExpr< AllocaExpr >(
                    std::move(ref), IntLitExp(APSIntFromUnsigned(aling)), nullptr, Token(),
                    Token());
            })
            .Case< mlir::LLVM::NullOp >([&](mlir::LLVM::NullOp op) -> ExprPtr {
                return MakeExpr< NullExpr >(Token(), Token());
            })
            .Case< mlir::LLVM::ConstantOp >([&](mlir::LLVM::ConstantOp op) {
                auto val = op.getValue();
                if (auto int_val = llvm::dyn_cast< mlir::IntegerAttr >(val)) {
                    auto signless = int_val.getValue();
                    return IntLit(llvm::APSInt(signless, false));
                } else if (auto float_val = llvm::dyn_cast< mlir::FloatAttr >(val)) {
                    return FloatLit(float_val.getValue());
                } else {
                    // TODO(ian)
                    throw UnhandledMLIRLift(
                        op->getLoc(), "No support for non integer/float constants");
                }
            })
            .Case< mlir::LLVM::LoadOp >([&](mlir::LLVM::LoadOp op) {
                auto ty = LiftType(op.getType());
                return MakeExpr< patchlang::LoadExpr >(
                    std::move(ty), op.getVolatile_(), this->GetRefExport(op.getAddr()), Token(),
                    Token());
            })
            .Case< mlir::LLVM::AddOp >([&](auto op) {
                // TODO(frabert): Handle nsw nuw
                return LiftBinOp< BinaryOp::Add >(op);
            })
            .Case< mlir::LLVM::FAddOp >([&](auto op) { return LiftBinOp< BinaryOp::Fadd >(op); })
            .Case< mlir::LLVM::SubOp >([&](auto op) {
                // TODO(frabert): Handle nsw nuw
                return LiftBinOp< BinaryOp::Sub >(op);
            })
            .Case< mlir::LLVM::FSubOp >([&](auto op) { return LiftBinOp< BinaryOp::Fsub >(op); })
            .Case< mlir::LLVM::MulOp >([&](auto op) {
                // TODO(frabert): Handle nsw nuw
                return LiftBinOp< BinaryOp::Mul >(op);
            })
            .Case< mlir::LLVM::FMulOp >([&](auto op) { return LiftBinOp< BinaryOp::Fmul >(op); })
            .Case< mlir::LLVM::UDivOp >([&](auto op) { return LiftBinOp< BinaryOp::Udiv >(op); })
            .Case< mlir::LLVM::SDivOp >([&](auto op) { return LiftBinOp< BinaryOp::Sdiv >(op); })
            .Case< mlir::LLVM::FDivOp >([&](auto op) { return LiftBinOp< BinaryOp::Fdiv >(op); })
            .Case< mlir::LLVM::SRemOp >([&](auto op) { return LiftBinOp< BinaryOp::Srem >(op); })
            .Case< mlir::LLVM::FRemOp >([&](auto op) { return LiftBinOp< BinaryOp::Frem >(op); })
            .Case< mlir::LLVM::ShlOp >([&](auto op) {
                // TODO(frabert): Handle nsw nuw
                return LiftBinOp< BinaryOp::Shl >(op);
            })
            .Case< mlir::LLVM::LShrOp >([&](auto op) { return LiftBinOp< BinaryOp::Lshr >(op); })
            .Case< mlir::LLVM::AShrOp >([&](auto op) { return LiftBinOp< BinaryOp::Ashr >(op); })
            .Case< mlir::LLVM::AndOp >([&](auto op) { return LiftBinOp< BinaryOp::And >(op); })
            .Case< mlir::LLVM::OrOp >([&](auto op) { return LiftBinOp< BinaryOp::Or >(op); })
            .Case< mlir::LLVM::XOrOp >([&](auto op) { return LiftBinOp< BinaryOp::Xor >(op); })
            .Case< mlir::LLVM::ICmpOp >([&](auto op) {
                switch (op.getPredicate()) {
                    case mlir::LLVM::ICmpPredicate::eq: return LiftBinOp< BinaryOp::Eq >(op);
                    case mlir::LLVM::ICmpPredicate::ne: return LiftBinOp< BinaryOp::Ne >(op);
                    case mlir::LLVM::ICmpPredicate::ugt: return LiftBinOp< BinaryOp::Ugt >(op);
                    case mlir::LLVM::ICmpPredicate::uge: return LiftBinOp< BinaryOp::Uge >(op);
                    case mlir::LLVM::ICmpPredicate::ult: return LiftBinOp< BinaryOp::Ult >(op);
                    case mlir::LLVM::ICmpPredicate::ule: return LiftBinOp< BinaryOp::Ule >(op);
                    case mlir::LLVM::ICmpPredicate::sgt: return LiftBinOp< BinaryOp::Sgt >(op);
                    case mlir::LLVM::ICmpPredicate::sge: return LiftBinOp< BinaryOp::Sge >(op);
                    case mlir::LLVM::ICmpPredicate::slt: return LiftBinOp< BinaryOp::Slt >(op);
                    case mlir::LLVM::ICmpPredicate::sle: return LiftBinOp< BinaryOp::Sle >(op);
                }
            })
            .Case< mlir::LLVM::FCmpOp >([&](auto op) {
                switch (op.getPredicate()) {
                    case mlir::LLVM::FCmpPredicate::oeq: return LiftBinOp< BinaryOp::Foeq >(op);
                    case mlir::LLVM::FCmpPredicate::ogt: return LiftBinOp< BinaryOp::Fogt >(op);
                    case mlir::LLVM::FCmpPredicate::oge: return LiftBinOp< BinaryOp::Foge >(op);
                    case mlir::LLVM::FCmpPredicate::olt: return LiftBinOp< BinaryOp::Folt >(op);
                    case mlir::LLVM::FCmpPredicate::ole: return LiftBinOp< BinaryOp::Fole >(op);
                    case mlir::LLVM::FCmpPredicate::one: return LiftBinOp< BinaryOp::Fone >(op);
                    case mlir::LLVM::FCmpPredicate::ord: return LiftBinOp< BinaryOp::Ford >(op);
                    case mlir::LLVM::FCmpPredicate::ueq: return LiftBinOp< BinaryOp::Fueq >(op);
                    case mlir::LLVM::FCmpPredicate::ugt: return LiftBinOp< BinaryOp::Fugt >(op);
                    case mlir::LLVM::FCmpPredicate::uge: return LiftBinOp< BinaryOp::Fuge >(op);
                    case mlir::LLVM::FCmpPredicate::ult: return LiftBinOp< BinaryOp::Fult >(op);
                    case mlir::LLVM::FCmpPredicate::ule: return LiftBinOp< BinaryOp::Fule >(op);
                    case mlir::LLVM::FCmpPredicate::une: return LiftBinOp< BinaryOp::Fune >(op);
                    case mlir::LLVM::FCmpPredicate::uno: return LiftBinOp< BinaryOp::Funo >(op);
                    case mlir::LLVM::FCmpPredicate::_true: return BoolLit(true);
                    case mlir::LLVM::FCmpPredicate::_false: return BoolLit(false);
                }
            })
            .Case< mlir::LLVM::CallOp >([&](mlir::LLVM::CallOp op) -> patchlang::ExprPtr {
                std::string callee = op.getCallee()->str();
                std::vector< ExprPtr > args;
                for (auto arg : op.getArgOperands()) {
                    args.push_back(this->GetRefExport(arg));
                }

                return MakeExpr< CallExpr >(
                    StrLitExpr(callee, Token()), std::move(args), Token(), Token());
            })
            .Case< mlir::LLVM::CallIntrinsicOp >(
                [&](mlir::LLVM::CallIntrinsicOp op) -> patchlang::ExprPtr {
                    std::string callee = op.getIntrin().str();
                    std::vector< ExprPtr > args;
                    for (auto arg : op.getArgs()) {
                        args.push_back(this->GetRefExport(arg));
                    }

                    return MakeExpr< CallIntrinsicExpr >(
                        StrLitExpr(callee, Token()), std::move(args), Token(), Token());
                })
            .Case< mlir::LLVM::TruncOp >(
                [&](auto op) -> patchlang::ExprPtr { return LiftCastOp< CastExpr::Trunc >(op); })
            .Case< mlir::LLVM::ZExtOp >(
                [&](auto op) -> patchlang::ExprPtr { return LiftCastOp< CastExpr::ZExt >(op); })
            .Case< mlir::LLVM::SExtOp >(
                [&](auto op) -> patchlang::ExprPtr { return LiftCastOp< CastExpr::SExt >(op); })
            .Case< mlir::LLVM::FPTruncOp >(
                [&](auto op) -> patchlang::ExprPtr { return LiftCastOp< CastExpr::FPTrunc >(op); })
            .Case< mlir::LLVM::FPExtOp >(
                [&](auto op) -> patchlang::ExprPtr { return LiftCastOp< CastExpr::FPExt >(op); })
            .Case< mlir::LLVM::FPToUIOp >(
                [&](auto op) -> patchlang::ExprPtr { return LiftCastOp< CastExpr::FPToUI >(op); })
            .Case< mlir::LLVM::FPToSIOp >(
                [&](auto op) -> patchlang::ExprPtr { return LiftCastOp< CastExpr::FPToSI >(op); })
            .Case< mlir::LLVM::UIToFPOp >(
                [&](auto op) -> patchlang::ExprPtr { return LiftCastOp< CastExpr::UIToFP >(op); })
            .Case< mlir::LLVM::SIToFPOp >(
                [&](auto op) -> patchlang::ExprPtr { return LiftCastOp< CastExpr::SIToFP >(op); })
            .Case< mlir::LLVM::PtrToIntOp >(
                [&](auto op) -> patchlang::ExprPtr { return LiftCastOp< CastExpr::PtrToInt >(op); })
            .Case< mlir::LLVM::IntToPtrOp >(
                [&](auto op) -> patchlang::ExprPtr { return LiftCastOp< CastExpr::IntToPtr >(op); })
            .Case< mlir::LLVM::BitcastOp >(
                [&](auto op) -> patchlang::ExprPtr { return LiftCastOp< CastExpr::BitCast >(op); })
            .Case< mlir::LLVM::GEPOp >([&](auto op) -> patchlang::ExprPtr {
                auto base = GetRefExport(op.getBase());
                // TODO(frabert): When is elemType nullopt?
                auto elem_type = LiftType(*op.getElemType());
                std::vector< ExprPtr > indices;
                for (llvm::PointerUnion< mlir::IntegerAttr, mlir::Value > index : op.getIndices()) {
                    if (index.is< mlir::IntegerAttr >()) {
                        auto ct       = index.get< mlir::IntegerAttr >();
                        auto signless = ct.getValue();
                        indices.push_back(MakeExpr< IntLitExpr >(
                            llvm::APSInt(signless, false), LitBase::Decimal, Token{}));
                    } else {
                        auto val = index.get< mlir::Value >();
                        indices.push_back(GetRefExport(val));
                    }
                }
                return MakeExpr< GetElementPtrExpr >(
                    std::move(base), std::move(elem_type), std::move(indices), Token{}, Token{});
            })
            .Case< mlir::LLVM::SelectOp >([&](auto op) {
                auto cond       = GetRefExport(op.getCondition());
                auto true_expr  = GetRefExport(op.getTrueValue());
                auto false_expr = GetRefExport(op.getFalseValue());
                return MakeExpr< SelectExpr >(
                    std::move(cond), std::move(true_expr), std::move(false_expr), Token{}, Token{});
            })
            .Default([&](auto& v) -> patchlang::ExprPtr {
                throw UnhandledMLIRLift(
                    op.getLoc(), "No expr match for " + op.getName().getStringRef().str());
            });
    }

    Stmt LifterContext::LiftOp(mlir::Operation& op) {
        if (op.getNumResults() == 0) {
            if (auto call = mlir::dyn_cast< mlir::LLVM::CallOp >(op)) {
                std::string callee = call.getCallee()->str();
                std::vector< ExprPtr > args;
                for (auto arg : call.getArgOperands()) {
                    args.push_back(this->GetRefExport(arg));
                }

                return CallStmt(StrLitExpr(callee, Token()), std::move(args), Token(), Token());
            } else if (auto call = mlir::dyn_cast< mlir::LLVM::CallIntrinsicOp >(op)) {
                std::string callee = call.getIntrin().str();
                std::vector< ExprPtr > args;
                for (auto arg : call.getArgs()) {
                    args.push_back(this->GetRefExport(arg));
                }

                return CallStmt(StrLitExpr(callee, Token()), std::move(args), Token(), Token());
            }
        }

        CHECK(op.getNumResults() == 1) << MLIRThingToString(op);
        if (op.hasOneUse()) {
            return NopStmt({}, {});
        }
        auto val = op.getResult(0);
        return BindExprForMLIRValue(LiftValue(val), val);
    }

    irene3::patchlang::Stmt LifterContext::LiftnonControlFlowOp(mlir::Operation& op) {
        return llvm::TypeSwitch< mlir::Operation&, patchlang::Stmt >(op)
            .Case< mlir::LLVM::StoreOp >([&](mlir::LLVM::StoreOp stop) -> Stmt {
                auto val  = stop.getValue();
                auto addr = stop.getAddr();
                return StoreStmt(
                    GetRefExport(val), GetRefExport(addr), stop.getVolatile_(), Token(), Token());
            })
            .Default([&](auto& v) -> patchlang::Stmt { return LiftOp(op); });
    }

    patchlang::IntLitExpr LifterContext::LowerBBCall(mlir::LLVM::CallOp cop) {
        CHECK(*cop.getCallee() == anvill::kAnvillGoto);
        auto val  = cop.getArgOperands().front();
        auto addr = val.getDefiningOp< mlir::LLVM::ConstantOp >();

        auto attr = mlir::cast< mlir::IntegerAttr >(addr.getValue());

        return IntLitExp(llvm::APSInt(attr.getValue(), true));
    }

    patchlang::IntLitExpr LifterContext::LowerOnlyControlFlowBlock(mlir::Block* block) {
        auto cop = firstOp< mlir::Block&, mlir::LLVM::CallOp >(*block);
        CHECK(cop);
        return LowerBBCall(*cop);
    }

    patchlang::ExprPtr LifterContext::GetRefExport(mlir::Value val) {
        // TODO(Ian): so what we need here is a map of values to names:
        // there are two ways names get values: a vaue producing op defines a let and
        // arguments get defined by the value expression that defines the argument
        auto index = value_index.find(val.getAsOpaquePointer());
        if (index != value_index.end()) {
            return MakeExpr< DeclRefExpr >(
                LifterContext::NameForIndex(index->second), Token(), Token(), Token());
        }

        auto op_ptr = val.getDefiningOp();
        if (!op_ptr) {
            throw UnhandledMLIRLift(
                val.getLoc(), "Unsupported value type " + MLIRThingToString(val));
        }
        return LiftValue(val);
    }

    void LifterContext::LowerTerminator(
        std::vector< patchlang::Stmt >& body, mlir::Operation* term) {
        if (auto cop = mlir::dyn_cast< mlir::LLVM::CallOp >(term)) {
            if (cop.getCallee() == anvill::kAnvillGoto) {
                auto tgt = this->LowerBBCall(cop);
                body.push_back(GotoStmt(std::move(tgt), Token(), Token()));
                return;
            }
        } else if (auto cbranch = mlir::dyn_cast< mlir::LLVM::CondBrOp >(term)) {
            ExprPtr ref    = this->GetRefExport(cbranch.getCondition());
            IntLitExpr lhs = this->LowerOnlyControlFlowBlock(cbranch.getTrueDest());
            IntLitExpr rhs = this->LowerOnlyControlFlowBlock(cbranch.getFalseDest());
            body.push_back(
                patchlang::ConditionalGotoStmt(std::move(lhs), std::move(ref), Token(), Token()));
            body.push_back(patchlang::GotoStmt(std::move(rhs), Token(), Token()));
            return;
        }
        body.push_back(patchlang::FailedToLiftStmt(
            patchlang::StrLitExpr(
                "Unhandled terminator for region: " + MLIRThingToString(*term), Token()),
            Token(), Token()));
    }

    void LifterContext::LiftArgs(
        std::vector< patchlang::Stmt >& body, patchir::CallOp cop, mlir::LLVM::LLVMFuncOp funcop) {
        size_t arg_ind = 0;
        for (auto arg : cop.getArgs()) {
            auto representing = funcop.getArgument(arg_ind);
            arg_ind += 1;
            auto vop = arg.getDefiningOp< patchir::ValueOp >();
            body.push_back(this->LiftValueOp(vop, representing));
        }
    }

    namespace
    {
        mlir::Operation* FindExecutableTerm(mlir::Operation* st) {
            auto curr = st;
            while (curr && mlir::isa< mlir::LLVM::UnreachableOp >(curr)) {
                curr = curr->getPrevNode();
            }
            return curr;
        }
    } // namespace

    void LifterContext::LiftBody(
        mlir::LLVM::LLVMFuncOp funcop, std::vector< patchlang::Stmt >& stmts) {
        auto& region = funcop.getFunctionBody();
        CHECK(region.getBlocks().size() <= 3);
        auto& entry_block = region.getBlocks().front();

        auto term = FindExecutableTerm(entry_block.getTerminator());
        for (auto& op : entry_block.getOperations()) {
            if (&op != term && !mlir::isa< mlir::LLVM::UnreachableOp >(op)) {
                stmts.push_back(LiftnonControlFlowOp(op));
            }
        }

        if (term) {
            this->LowerTerminator(stmts, term);
        } else {
            stmts.push_back(patchlang::FailedToLiftStmt(
                patchlang::StrLitExpr(
                    "no terminator for region: " + funcop.getSymName().str(), Token()),
                Token(), Token()));
        }
    }

    Stmt LifterContext::BindExprForMLIRValue(patchlang::ExprPtr expr, mlir::Value val) {
        return LetDeclStmt(this->GetValueName(val), std::move(expr), Token(), Token());
    }

    std::optional< patchlang::Location > LifterContext::LiftLoc(
        std::optional< mlir::Attribute > vop) {
        if (!vop) {
            return std::nullopt;
        }

        auto loc = *vop;

        return llvm::TypeSwitch< mlir::Attribute, patchlang::Location >(loc)
            .Case< patchir::RegisterAttr >([&](patchir::RegisterAttr reg) -> patchlang::Location {
                return patchlang::RegisterLocation(
                    reg.getReg().str(), IntLitExp(APSIntFromUnsigned(reg.getSizeBits())), Token(),
                    Token(), Token());
            })
            .Case< patchir::MemoryIndirectAttr >(
                [&](patchir::MemoryIndirectAttr memind) -> patchlang::Location {
                    auto base = memind.getBase().str();
                    return patchlang::IndirectMemoryLocation(
                        base, IntLitExp(APSIntFromSigned(memind.getOffset())),
                        IntLitExp(APSIntFromUnsigned(memind.getSizeBits())), Token(), Token(),
                        Token());
                })
            .Case< patchir::MemoryAttr >([&](patchir::MemoryAttr mem) -> patchlang::Location {
                return patchlang::MemoryLocation(
                    IntLitExp(APSIntFromUnsigned(mem.getAddr())),
                    IntLitExp(APSIntFromUnsigned(mem.getSizeBits())),
                    IntLitExp(APSIntFromSigned(mem.getDisp())),
                    BoolLitExpr(mem.getIsExternal(), Token()), Token(), Token());
            })

            .Default([&](auto v) -> patchlang::Location {
                throw patchlang::UnhandledMLIRLift(
                    std::nullopt, "Unhandled loc: " + MLIRThingToString(loc));
            });
    }

    Stmt LifterContext::LiftValueOp(patchir::ValueOp vop, mlir::Value representing) {
        auto lifted_ty = this->LiftType(vop.getType().getElement());

        return ValueStmt(
            this->GetValueName(representing, vop.getNameAttr().str()),
            this->LiftLoc(vop.getAtEntry()), this->LiftLoc(vop.getAtExit()), std::move(lifted_ty),
            Token(), Token(), Token());
    }

    patchlang::ExternalGlobal LifterContext::LiftGlobal(patchir::Global gv) {
        auto mem = gv.getMem();
        irene3::patchlang::IntLitExpr func_addr(
            llvm::APSInt::getUnsigned(mem.getAddr()), irene3::patchlang::LitBase::Hexadecimal, {});
        irene3::patchlang::IntLitExpr func_disp(
            llvm::APSInt::get(mem.getDisp()), irene3::patchlang::LitBase::Decimal, {});
        irene3::patchlang::BoolLitExpr func_ext(mem.getIsExternal(), {});
        irene3::patchlang::IntLitExpr bit_size(
            llvm::APSInt::getUnsigned(mem.getSizeBits()), irene3::patchlang::LitBase::Decimal, {});

        return ExternalGlobal(
            std::move(func_addr), std::move(func_disp), std::move(func_ext), std::move(bit_size),
            gv.getTargetSymName().str(), LiftType(gv.getHighType()), Token(), Token(), Token());
    }

    patchlang::External LifterContext::LiftExternal(patchir::FunctionOp fop) {
        irene3::patchlang::IntLitExpr func_addr(
            llvm::APSInt::getUnsigned(fop.getAddress()), irene3::patchlang::LitBase::Hexadecimal,
            {});
        irene3::patchlang::IntLitExpr func_disp(
            llvm::APSInt::get(fop.getDisp()), irene3::patchlang::LitBase::Decimal, {});
        irene3::patchlang::BoolLitExpr func_ext(fop.getIsExternal(), {});

        std::string orig_nm = fop.getName().str();

        auto llvm_repr = this->mod.lookupSymbol< mlir::LLVM::LLVMFuncOp >(orig_nm);

        auto ftype = llvm_repr.getFunctionType();
        std::vector< patchlang::TypePtr > type_range;

        for (auto rty : ftype.getParams()) {
            type_range.push_back(this->LiftType(rty));
        }

        return External(
            std::move(func_addr), std::move(func_disp), std::move(func_ext), orig_nm,
            this->LiftType(ftype.getReturnType()), std::move(type_range), Token(), Token(),
            Token());
    }

    TypeDecl LifterContext::AddNamedType(std::string s, mlir::Type ty) {
        auto decl = TypeDecl(s, LiftType(ty), Token(), Token(), Token());
        this->named_types.insert({ ty, s });

        return decl;
    }

    std::vector< irene3::patchlang::StackOffset > LifterContext::LiftStackOffsets(
        mlir::ArrayAttr arr) {
        std::vector< StackOffset > offs;
        for (auto attr : arr) {
            patchir::StackOffsetAttr off = mlir::cast< patchir::StackOffsetAttr >(attr);
            auto loc = std::get< patchlang::RegisterLocation >(*LiftLoc(off.getReg()));
            LOG(INFO) << "pushing stack offset";
            offs.push_back(
                StackOffset(loc, IntLitExp(APSIntFromSigned(off.getOffset())), Token(), Token()));
        }

        return offs;
    }

    irene3::patchlang::Region LifterContext::LiftRegion(
        irene3::patchir::RegionOp reg_op, bool as_definition) {
        auto cop = irene3::firstOp< patchir::RegionOp, patchir::CallOp >(reg_op);
        if (!cop) {
            std::string ss;
            llvm::raw_string_ostream ro(ss);
            cop->getLoc()->print(ro);
            LOG(FATAL) << "Invalid region, expected call " << ss;
        }

        auto mod    = mlir::cast< mlir::ModuleOp >(reg_op->getParentOp()->getParentOp());
        auto llfunc = mod.lookupSymbol(cop->getCallee());
        auto func   = mlir::cast< mlir::LLVM::LLVMFuncOp >(llfunc);

        std::vector< patchlang ::Stmt > body;
        this->LiftArgs(body, *cop, func);
        if (as_definition) {
            this->LiftBody(func, body);
            body.erase(
                std::remove_if(
                    body.begin(), body.end(),
                    [](const auto& stmt) {
                        return std::holds_alternative< patchlang::NopStmt >(stmt);
                    }),
                body.end());
        }

        auto offs_ent  = this->LiftStackOffsets(reg_op.getEntryStackOffsetsAttr());
        auto offs_exit = this->LiftStackOffsets(reg_op.getExitStackOffsetsAttr());

        auto addr                  = IntLitExp(APSIntFromUnsigned(reg_op.getAddress()));
        auto size                  = IntLitExp(APSIntFromUnsigned(reg_op.getSizeBytes()));
        auto stack_offset_at_entry = IntLitExp(reg_op.getStackOffsetEntryBytesAttr().getAPSInt());
        auto stack_offset_at_exit  = IntLitExp(reg_op.getStackOffsetEntryBytesAttr().getAPSInt());
        auto uid                   = IntLitExp(APSIntFromUnsigned(reg_op.getUid()));

        return Region(
            std::move(body), std::move(addr), std::move(size), std::move(stack_offset_at_entry),
            std::move(stack_offset_at_exit), std::move(uid), std::move(offs_ent),
            std::move(offs_exit), Token(), Token());
    }

    PModule LiftPatchLangModule(
        mlir::MLIRContext& context, mlir::ModuleOp mod, std::optional< uint64_t > target_uid) {
        irene3::patchlang::LifterContext lifter(context, mod);
        std::vector< irene3::patchlang::LangDecl > decls;

        // Note(Ian): So we need to only lift types that we name here so they need to be added to a
        // mapping
        for (auto glbl : mod.getOps< mlir::LLVM::GlobalOp >()) {
            auto ty = glbl.getGlobalType();
            if (auto sty = mlir::dyn_cast< mlir::LLVM::LLVMStructType >(ty)) {
                if (!sty.getName().empty()) {
                    decls.push_back(lifter.AddNamedType(sty.getName().str(), sty));
                }
            }
        }

        for (auto gv_op : mod.getOps< irene3::patchir::Global >()) {
            decls.push_back(lifter.LiftGlobal(gv_op));
        }

        for (auto fop : mod.getOps< irene3::patchir::FunctionOp >()) {
            // A function without a region is an external that we should create a reference for
            // externs are placed before the target so they are in scope.
            if (fop.getRegion().empty() || fop.getBody().getOps().empty()) {
                decls.push_back(lifter.LiftExternal(fop));
                continue;
            }
            irene3::patchlang::IntLitExpr func_addr(
                llvm::APSInt::getUnsigned(fop.getAddress()),
                irene3::patchlang::LitBase::Hexadecimal, {});
            irene3::patchlang::IntLitExpr func_disp(
                llvm::APSInt::get(fop.getDisp()), irene3::patchlang::LitBase::Decimal, {});
            irene3::patchlang::BoolLitExpr func_ext(fop.getIsExternal(), {});

            std::vector< irene3::patchlang::Region > regs;
            for (auto rop : fop.getOps< irene3::patchir::RegionOp >()) {
                // If we specify a UID, only lift that region as a definition.
                // Otherwise, lift everything as a definition.
                regs.emplace_back(
                    lifter.LiftRegion(rop, !target_uid || *target_uid == rop.getUid()));
            }
            irene3::patchlang::Function func(
                std::move(regs), std::move(func_addr), std::move(func_disp), std::move(func_ext),
                fop.getName().str(), {}, {}, {});
            decls.push_back(std::move(func));
        }

        auto target
            = mlir::cast< mlir::StringAttr >(
                  mod.getOperation()->getAttr(mlir::LLVM::LLVMDialect::getTargetTripleAttrName()))
                  .str();

        auto datalayout
            = mlir::cast< mlir::StringAttr >(
                  mod.getOperation()->getAttr(mlir::LLVM::LLVMDialect::getDataLayoutAttrName()))
                  .str();

        auto image_base = mlir::cast< mlir::IntegerAttr >(
                              mod.getOperation()->getAttr(
                                  irene3::patchir::PatchIRDialect::getImageBaseAttrName()))
                              .getAPSInt();

        irene3::patchlang::PModule pmod(
            irene3::patchlang::StrLitExpr(datalayout, irene3::patchlang::Token()),
            irene3::patchlang::StrLitExpr(target, irene3::patchlang::Token()),
            irene3::patchlang::IntLitExpr(
                image_base, irene3::patchlang::LitBase::Hexadecimal, irene3::patchlang::Token()),
            std::move(decls), irene3::patchlang::Token(), irene3::patchlang::Token());

        return pmod;
    }

} // namespace irene3::patchlang
