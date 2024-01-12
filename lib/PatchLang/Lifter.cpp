#include <anvill/ABI.h>
#include <anvill/Result.h>
#include <functional>
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
#include <mlir/IR/Operation.h>
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
            .Case< mlir::LLVM::ConstantOp >([&](mlir::LLVM::ConstantOp op) {
                auto val = op.getValue();
                if (auto int_val = llvm::dyn_cast< mlir::IntegerAttr >(val)) {
                    auto signless = int_val.getValue();
                    return IntLit(llvm::APSInt(signless, false));
                } else {
                    // TODO(ian)
                    throw UnhandledMLIRLift(op->getLoc(), "No support for non integer constants");
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
            .Case< mlir::LLVM::CallOp >([&](mlir::LLVM::CallOp op) -> patchlang::ExprPtr {
                std::string callee = op.getCallee()->str();
                std::vector< ExprPtr > args;
                for (auto arg : op.getArgOperands()) {
                    args.push_back(this->GetRefExport(arg));
                }

                return MakeExpr< CallExpr >(
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
            .Default([&](auto& v) -> patchlang::ExprPtr {
                throw UnhandledMLIRLift(
                    op.getLoc(), "No expr match for " + op.getName().getStringRef().str());
            });
    }

    Stmt LifterContext::LiftOp(mlir::Operation& op) {
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

    patchlang::ExprPtr LifterContext::LowerBBCall(mlir::LLVM::CallOp cop) {
        CHECK(*cop.getCallee() == anvill::kAnvillGoto);
        auto val  = cop.getArgOperands().front();
        auto addr = val.getDefiningOp< mlir::LLVM::ConstantOp >();
        auto attr = mlir::cast< mlir::IntegerAttr >(addr.getValue());

        return IntLit(llvm::APSInt(attr.getValue(), true));
    }

    patchlang::ExprPtr LifterContext::LowerOnlyControlFlowBlock(mlir::Block* block) {
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
            ExprPtr ref = this->GetRefExport(cbranch.getCondition());
            ExprPtr lhs = this->LowerOnlyControlFlowBlock(cbranch.getTrueDest());
            ExprPtr rhs = this->LowerOnlyControlFlowBlock(cbranch.getFalseDest());
            auto sel    = MakeExpr< patchlang::SelectExpr >(
                std::move(ref), std::move(lhs), std::move(rhs), Token(), Token());
            body.push_back(patchlang::GotoStmt(std::move(sel), Token(), Token()));
            return;
        }
        LOG(FATAL) << "Unhandled terminator " << MLIRThingToString(*term);
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

        CHECK(!!term) << MLIRThingToString(entry_block.getParentOp()->getLoc())
                      << ": Region lacks a proper terminator";
        this->LowerTerminator(stmts, term);
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
            this->GetValueName(representing), this->LiftLoc(vop.getAtEntry()),
            this->LiftLoc(vop.getAtExit()), std::move(lifted_ty), Token(), Token(), Token());
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

        auto addr                  = IntLitExp(APSIntFromUnsigned(reg_op.getAddress()));
        auto size                  = IntLitExp(APSIntFromUnsigned(reg_op.getSizeBytes()));
        auto stack_offset_at_entry = IntLitExp(reg_op.getStackOffsetEntryBytesAttr().getAPSInt());
        auto stack_offset_at_exit  = IntLitExp(reg_op.getStackOffsetEntryBytesAttr().getAPSInt());
        auto uid                   = IntLitExp(APSIntFromUnsigned(reg_op.getUid()));

        return Region(
            std::move(body), std::move(addr), std::move(size), std::move(stack_offset_at_entry),
            std::move(stack_offset_at_exit), std::move(uid), Token(), Token());
    }
} // namespace irene3::patchlang
