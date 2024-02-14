#pragma once

#include "Exprs.h"
#include "Locations.h"
#include "Stmt.h"
#include "Types.h"

#include <algorithm>
#include <iomanip>
#include <ios>
#include <llvm/ADT/APFloat.h>
#include <llvm/Support/raw_os_ostream.h>
#include <llvm/Support/raw_ostream.h>
#include <type_traits>
#include <variant>

namespace irene3::patchlang
{
    namespace detail
    {
        void PrintName(auto&& os, const std::string& s) {
            if (std::all_of(
                    s.begin(), s.end(),
                    [](char c) {
                        return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')
                               || (c >= 'A' && c <= 'Z');
                    })
                && s != "true" && s != "false" && s != "null") {
                os << s;
            } else {
                os << std::quoted(s);
            }
        }
        template< typename T >
        concept LLVMStream = std::derived_from< std::remove_cvref_t< T >, llvm::raw_ostream >;

        template< typename T >
        concept StdStream = std::derived_from< std::remove_cvref_t< T >, std::ostream >;
    } // namespace detail

    template< IsType T >
    void PrintSExpr(auto&& os, const T& type, int indent = 0) {
        std::visit([&os, indent](const auto& type) { PrintSExpr(os, type, indent); }, type);
    }

    template< IsExpr T >
    void PrintSExpr(auto&& os, const T& expr, int indent = 0) {
        std::visit([&os, indent](const auto& expr) { PrintSExpr(os, expr, indent); }, expr);
    }

    void PrintSExpr(auto&& os, const Location& loc, int indent = 0) {
        std::visit([&os, indent](const auto& loc) { PrintSExpr(os, loc, indent); }, loc);
    }

    template< IsStmt T >
    void PrintSExpr(auto&& os, const T& stmt, int indent = 0) {
        std::visit([&os, indent](const auto& stmt) { PrintSExpr(os, stmt, indent); }, stmt);
    }

    void PrintSExpr(auto&& os, const FloatLitExpr& expr, int indent = 0) {
        os << "0x" << std::hex << expr.GetValue().bitcastToAPInt().getZExtValue() << ':';
        auto sema = llvm::APFloatBase::SemanticsToEnum(expr.GetValue().getSemantics());

        using llvm::APFloatBase;
        switch (sema) {
            case APFloatBase::Semantics::S_IEEEhalf: os << "f16"; break;
            case APFloatBase::Semantics::S_BFloat: os << "bf16"; break;
            case APFloatBase::Semantics::S_IEEEsingle: os << "f32"; break;
            case APFloatBase::Semantics::S_IEEEdouble: os << "f64"; break;
            case APFloatBase::Semantics::S_IEEEquad: os << "f128"; break;
            case APFloatBase::Semantics::S_Float8E5M2: os << "f8e5m2"; break;
            case APFloatBase::Semantics::S_Float8E5M2FNUZ: os << "f8e5m2fnuz"; break;
            case APFloatBase::Semantics::S_Float8E4M3FN: os << "f8e4m3fn"; break;
            case APFloatBase::Semantics::S_Float8E4M3FNUZ: os << "f8e4m3fnuz"; break;
            case APFloatBase::Semantics::S_Float8E4M3B11FNUZ: os << "f8e4m3b11fnuz"; break;
            case APFloatBase::Semantics::S_FloatTF32: os << "tf32"; break;
            case APFloatBase::Semantics::S_x87DoubleExtended: os << "f80"; break;
            default: os << "<<unsupported>>"; break;
        }
    }

    template< detail::LLVMStream T >
    void PrintSExpr(T&& os, const FloatLitExpr& expr, int ident = 0) {
        auto value = expr.GetValue();
        value.print(os);
    }

    template< detail::StdStream T >
    void PrintSExpr(T&& os, const FloatLitExpr& expr, int indent = 0) {
        PrintSExpr(llvm::raw_os_ostream(os), expr, indent);
    }

    void PrintSExpr(auto&& os, const IntLitExpr& expr, int indent = 0) {
        auto value = expr.GetValue();
        if (value.isSigned()) {
            if (value.isNonNegative()) {
                os << '+';
            }
            switch (expr.GetBase()) {
                case LitBase::Decimal: os << std::dec << expr.GetValue().getExtValue(); break;
                case LitBase::Binary: // TODO: Not implemented yet
                case LitBase::Hexadecimal:
                    os << "0x" << std::hex << expr.GetValue().getExtValue();
                    break;
                case LitBase::Octal: os << '0' << std::oct << expr.GetValue().getExtValue(); break;
            }
        } else {
            switch (expr.GetBase()) {
                case LitBase::Decimal: os << std::dec << expr.GetValue().getZExtValue(); break;
                case LitBase::Binary: // TODO: Not implemented yet
                case LitBase::Hexadecimal:
                    os << "0x" << std::hex << expr.GetValue().getZExtValue();
                    break;
                case LitBase::Octal: os << '0' << std::oct << expr.GetValue().getZExtValue(); break;
            }
        }
        os << ':' << std::dec << value.getBitWidth();
    }

    void PrintSExpr(auto&& os, const AddrOf& expr, int indent = 0) {
        os << "(addrof\n";
        indent += 4;
        PrintSExpr(os, expr.GetGValue(), indent);
        os << ')';
    }

    void PrintSExpr(auto&& os, const BoolLitExpr& expr, int indent = 0) {
        os << (expr.GetValue() ? "true" : "false");
    }

    void PrintSExpr(auto&& os, const NullExpr& expr, int indent = 0) { os << "null"; }

    void PrintSExpr(auto&& os, const StrLitExpr& expr, int indent = 0) {
        os << std::quoted(expr.GetValue());
    }

    void PrintSExpr(auto&& os, const SelectExpr& expr, int indent = 0) {
        os << "(select\n";
        indent += 4;
        os << std::string(indent, ' ') << "cond: ";
        PrintSExpr(os, expr.GetCondition(), indent);
        os << '\n' << std::string(indent, ' ') << "if_true: ";
        PrintSExpr(os, expr.GetTrueCase(), indent);
        os << '\n' << std::string(indent, ' ') << "if_false: ";
        PrintSExpr(os, expr.GetFalseCase(), indent);
        os << ')';
    }

    void PrintSExpr(auto&& os, const DeclRefExpr& expr, int indent = 0) {
        detail::PrintName(os, expr.GetName());
    }

    void PrintSExpr(auto&& os, const BinaryExpr& expr, int indent = 0) {
        switch (expr.GetOp()) {
            case BinaryOp::Add: os << "(add\n"; break;
            case BinaryOp::Fadd: os << "(fadd\n"; break;
            case BinaryOp::Sub: os << "(sub\n"; break;
            case BinaryOp::Fsub: os << "(fsub\n"; break;
            case BinaryOp::Mul: os << "(mul\n"; break;
            case BinaryOp::Fmul: os << "(fmul\n"; break;
            case BinaryOp::Udiv: os << "(udiv\n"; break;
            case BinaryOp::Sdiv: os << "(sdiv\n"; break;
            case BinaryOp::Fdiv: os << "(fdiv\n"; break;
            case BinaryOp::Srem: os << "(srem\n"; break;
            case BinaryOp::Frem: os << "(frem\n"; break;
            case BinaryOp::Shl: os << "(shl\n"; break;
            case BinaryOp::Lshr: os << "(lshr\n"; break;
            case BinaryOp::Ashr: os << "(ashr\n"; break;
            case BinaryOp::And: os << "(and\n"; break;
            case BinaryOp::Or: os << "(or\n"; break;
            case BinaryOp::Xor: os << "(xor\n"; break;

            case BinaryOp::Eq: os << "(eq\n"; break;
            case BinaryOp::Ne: os << "(ne\n"; break;
            case BinaryOp::Ugt: os << "(ugt\n"; break;
            case BinaryOp::Uge: os << "(uge\n"; break;
            case BinaryOp::Ult: os << "(ult\n"; break;
            case BinaryOp::Ule: os << "(ule\n"; break;
            case BinaryOp::Sgt: os << "(sgt\n"; break;
            case BinaryOp::Sge: os << "(sge\n"; break;
            case BinaryOp::Slt: os << "(slt\n"; break;
            case BinaryOp::Sle: os << "(sle\n"; break;

            case BinaryOp::Foeq: os << "(foeq\n"; break;
            case BinaryOp::Fogt: os << "(fogt\n"; break;
            case BinaryOp::Foge: os << "(foge\n"; break;
            case BinaryOp::Folt: os << "(folt\n"; break;
            case BinaryOp::Fole: os << "(fole\n"; break;
            case BinaryOp::Fone: os << "(fone\n"; break;
            case BinaryOp::Ford: os << "(ford\n"; break;
            case BinaryOp::Fueq: os << "(fueq\n"; break;
            case BinaryOp::Fugt: os << "(fugt\n"; break;
            case BinaryOp::Fuge: os << "(fuge\n"; break;
            case BinaryOp::Fult: os << "(fult\n"; break;
            case BinaryOp::Fule: os << "(fule\n"; break;
            case BinaryOp::Fune: os << "(fune\n"; break;
            case BinaryOp::Funo: os << "(funo\n"; break;

            case BinaryOp::AddNuw: os << "(add nuw\n"; break;
            case BinaryOp::AddNsw: os << "(add nsw\n"; break;
            case BinaryOp::AddNuwNsw: os << "(add nuw nsw\n"; break;
            case BinaryOp::SubNuw: os << "(sub nuw\n"; break;
            case BinaryOp::SubNsw: os << "(sub nsw\n"; break;
            case BinaryOp::SubNuwNsw: os << "(sub nuw nsw\n"; break;
            case BinaryOp::MulNuw: os << "(mul nuw\n"; break;
            case BinaryOp::MulNsw: os << "(mul nsw\n"; break;
            case BinaryOp::MulNuwNsw: os << "(mul nuw nsw\n"; break;
            case BinaryOp::ShlNuw: os << "(shl nuw\n"; break;
            case BinaryOp::ShlNsw: os << "(shl nsw\n"; break;
            case BinaryOp::ShlNuwNsw: os << "(shl nuw nsw\n"; break;
        }
        indent += 4;
        os << std::string(indent, ' ');
        PrintSExpr(os, expr.GetLHS(), indent);
        os << '\n' << std::string(indent, ' ');
        PrintSExpr(os, expr.GetRHS(), indent);
        os << ')';
    }

    void PrintSExpr(auto&& os, const UnaryExpr& expr, int indent = 0) {
        // TODO: Not implemented
    }

    void PrintSExpr(auto&& os, const GetElementPtrExpr& expr, int indent = 0) {
        os << "(getelementptr\n";
        indent += 4;
        os << std::string(indent, ' ');
        PrintSExpr(os, expr.GetBase(), indent);
        os << '\n' << std::string(indent, ' ');
        PrintSExpr(os, expr.ElementType(), indent);
        for (auto& index : expr.GetIndices()) {
            os << '\n' << std::string(indent, ' ');
            PrintSExpr(os, *index, indent);
        }
        os << ')';
    }

    void PrintSExpr(auto&& os, const CallExpr& expr, int indent = 0) {
        indent += 4;
        os << "(call\n" << std::string(indent, ' ') << "callee: ";
        PrintSExpr(os, expr.GetCallee(), indent);
        for (auto& arg : expr.GetArgs()) {
            os << '\n' << std::string(indent, ' ');
            PrintSExpr(os, *arg, indent);
        }
        os << ')';
    }

    void PrintSExpr(auto&& os, const CallIntrinsicExpr& expr, int indent = 0) {
        indent += 4;
        os << "(intrinsic\n" << std::string(indent, ' ') << "callee: ";
        PrintSExpr(os, expr.GetCallee(), indent);
        for (auto& arg : expr.GetArgs()) {
            os << '\n' << std::string(indent, ' ');
            PrintSExpr(os, *arg, indent);
        }
        os << ')';
    }

    void PrintSExpr(auto&& os, const AllocaExpr& expr, int indent = 0) {
        indent += 4;
        os << "(alloca\n" << std::string(indent, ' ') << "alignment: ";
        PrintSExpr(os, expr.GetAlignment(), indent);
        os << '\n' << std::string(indent, ' ') << "type: ";
        PrintSExpr(os, expr.GetType(), indent);
        os << '\n' << std::string(indent, ' ') << "arraySize: ";
        PrintSExpr(os, expr.GetArraySize(), indent);
        os << ')';
    }

    void PrintSExpr(auto&& os, const LoadExpr& expr, int indent = 0) {
        indent += 4;
        os << "(load\n" << std::string(indent, ' ') << "type: ";
        PrintSExpr(os, expr.GetType(), indent);
        os << '\n' << std::string(indent, ' ');
        PrintSExpr(os, expr.GetPointer(), indent);
        os << ')';
    }

    void PrintSExpr(auto&& os, const CastExpr& expr, int indent = 0) {
        indent += 4;
        switch (expr.GetKind()) {
            case CastExprKind::Trunc: os << "(trunc\n"; break;
            case CastExprKind::ZExt: os << "(zext\n"; break;
            case CastExprKind::SExt: os << "(sext\n"; break;
            case CastExprKind::FPTrunc: os << "(fptrunc\n"; break;
            case CastExprKind::FPExt: os << "(fpext\n"; break;
            case CastExprKind::FPToUI: os << "(fptoui\n"; break;
            case CastExprKind::FPToSI: os << "(fptosi\n"; break;
            case CastExprKind::UIToFP: os << "(uitofp\n"; break;
            case CastExprKind::SIToFP: os << "(sitofp\n"; break;
            case CastExprKind::PtrToInt: os << "(ptrtoint\n"; break;
            case CastExprKind::IntToPtr: os << "(inttoptr\n"; break;
            case CastExprKind::BitCast: os << "(bitcast\n"; break;
        }
        os << std::string(indent, ' ') << "type: ";
        PrintSExpr(os, expr.GetType(), indent);
        os << '\n' << std::string(indent, ' ');
        PrintSExpr(os, expr.GetValue(), indent);
        os << ')';
    }

    void PrintSExpr(auto&& os, const PrimitiveType& type, int indent = 0) { os << type.GetName(); }

    void PrintSExpr(auto&& os, const StructType& type, int indent = 0) {
        os << "(struct";
        indent += 4;
        for (auto& elem : type.GetElements()) {
            os << '\n' << std::string(indent, ' ');
            PrintSExpr(os, *elem, indent);
        }
        os << ')';
    }

    void PrintSExpr(auto&& os, const ArrayType& type, int indent = 0) {
        os << "(array\n";
        indent += 4;
        os << std::string(indent, ' ') << "size: ";
        PrintSExpr(os, type.GetSize(), indent);
        os << '\n' << std::string(indent, ' ') << "type: ";
        PrintSExpr(os, type.GetType(), indent);
        os << ')';
    }

    void PrintSExpr(auto&& os, const VectorType& type, int indent = 0) {
        os << "(vector\n";
        indent += 4;
        os << std::string(indent, ' ') << "size: ";
        PrintSExpr(os, type.GetSize(), indent);
        os << '\n' << std::string(indent, ' ') << "type: ";
        PrintSExpr(os, type.GetType(), indent);
        os << ')';
    }

    void PrintSExpr(auto&& os, const RegisterLocation& loc, int indent = 0) {
        os << "(register name: " << loc.GetRegisterName() << " size: ";
        PrintSExpr(os, loc.GetSize(), indent);
        os << ')';
    }

    void PrintSExpr(auto&& os, const MemoryLocation& loc, int indent = 0) {
        indent += 4;
        os << "(memory\n" << std::string(indent, ' ') << "address: ";
        PrintSExpr(os, loc.GetAddress(), indent);
        os << '\n' << std::string(indent, ' ') << "size: ";
        PrintSExpr(os, loc.GetSize(), indent);
        os << '\n' << std::string(indent, ' ') << "displacement: ";
        PrintSExpr(os, loc.GetDisp(), indent);
        os << '\n' << std::string(indent, ' ') << "is_external: ";
        PrintSExpr(os, loc.GetIsExternal(), indent);
        os << ')';
    }

    void PrintSExpr(auto&& os, const IndirectMemoryLocation& loc, int indent = 0) {
        indent += 4;
        os << "(memory_indirect\n"
           << std::string(indent, ' ') << "base: " << loc.GetBaseName() << '\n';
        os << std::string(indent, ' ') << "offset: ";
        PrintSExpr(os, loc.GetOffset(), indent);
        os << '\n' << std::string(indent, ' ') << "size: ";
        PrintSExpr(os, loc.GetSize(), indent);
        os << ')';
    }

    void PrintSExpr(auto&& os, const LetDeclStmt& stmt, int indent = 0) {
        indent += 4;
        os << "(let " << stmt.GetName() << '\n' << std::string(indent, ' ');
        PrintSExpr(os, stmt.GetExpr(), indent);
        os << ')';
    }

    void PrintSExpr(auto&& os, const StoreStmt& stmt, int indent = 0) {
        indent += 4;
        os << "(store\n" << std::string(indent, ' ');
        PrintSExpr(os, stmt.GetValue(), indent);
        os << '\n' << std::string(indent, ' ');
        PrintSExpr(os, stmt.GetDestination(), indent);
        os << ')';
    }

    void PrintSExpr(auto&& os, const ReturnStmt& stmt, int indent = 0) {
        indent += 4;
        if (!stmt.GetValue().has_value()) {
            os << "(return)";
            return;
        }

        os << "(return\n" << std::string(indent, ' ');
        auto& value = stmt.GetValue()->get();
        PrintSExpr(os, value, indent);
        os << ')';
    }

    void PrintSExpr(auto&& os, const CallStmt& stmt, int indent = 0) {
        indent += 4;
        os << "(call\n" << std::string(indent, ' ') << "callee: ";
        PrintSExpr(os, stmt.GetCallee(), indent);
        for (auto& arg : stmt.GetArgs()) {
            os << '\n' << std::string(indent, ' ');
            PrintSExpr(os, *arg, indent);
        }
        os << ')';
    }

    void PrintSExpr(auto&& os, const CallIntrinsicStmt& stmt, int indent = 0) {
        indent += 4;
        os << "(intrinsic\n" << std::string(indent, ' ') << "callee: ";
        PrintSExpr(os, stmt.GetCallee(), indent);
        for (auto& arg : stmt.GetArgs()) {
            os << '\n' << std::string(indent, ' ');
            PrintSExpr(os, *arg, indent);
        }
        os << ')';
    }

    void PrintSExpr(auto&& os, const ValueStmt& stmt, int indent = 0) {
        indent += 4;
        os << "(value " << stmt.GetName();
        os << ' ';
        PrintSExpr(os, stmt.GetValueType());

        if (stmt.GetLocationAtEntry()) {
            os << '\n' << std::string(indent, ' ') << "at_entry: ";
            PrintSExpr(os, *stmt.GetLocationAtEntry(), indent);
        }
        if (stmt.GetLocationAtExit()) {
            os << '\n' << std::string(indent, ' ') << "at_exit: ";
            PrintSExpr(os, *stmt.GetLocationAtExit(), indent);
        }
        os << ')';
    }

    void PrintSExpr(auto&& os, const GotoStmt& stmt, int indent = 0) {
        indent += 4;
        os << "(goto\n" << std::string(indent, ' ');
        PrintSExpr(os, stmt.GetTarget(), indent);
        os << ')';
    }

    void PrintSExpr(auto&& os, const FailedToLiftStmt& stmt, int indent = 0) {
        indent += 4;
        os << "(failed_to_lift\n" << std::string(indent, ' ');
        PrintSExpr(os, stmt.GetMessage(), indent);
        os << ')';
    }

    void PrintSExpr(auto&& os, const ConditionalGotoStmt& stmt, int indent = 0) {
        indent += 4;
        os << "(cond_goto\n" << std::string(indent, ' ');
        PrintSExpr(os, stmt.GetTarget(), indent);
        os << '\n' << std::string(indent, ' ');
        PrintSExpr(os, stmt.GetCond(), indent);
        os << ')';
    }

    void PrintSExpr(auto&& os, const NopStmt& stmt, int indent = 0) { os << "(nop)"; }

    void PrintSExpr(auto&& os, const Region& reg, int indent = 0) {
        indent += 4;
        os << "(region\n" << std::string(indent, ' ') << "address: ";
        PrintSExpr(os, reg.GetAddress(), indent);
        os << '\n' << std::string(indent, ' ') << "size: ";
        PrintSExpr(os, reg.GetSize(), indent);
        os << '\n' << std::string(indent, ' ') << "stack_offset_at_entry: ";
        PrintSExpr(os, reg.GetStackOffsetAtEntry(), indent);
        os << '\n' << std::string(indent, ' ') << "stack_offset_at_exit: ";
        PrintSExpr(os, reg.GetStackOffsetAtExit(), indent);
        os << '\n' << std::string(indent, ' ') << "region_uid: ";
        PrintSExpr(os, reg.GetUID(), indent);
        for (auto& stmt : reg.GetBody()) {
            os << '\n' << std::string(indent, ' ');
            PrintSExpr(os, stmt, indent);
        }
        os << ')';
    }

    void PrintSExpr(auto&& os, const External& reg, int indent = 0) {
        indent += 4;
        os << "(external\n" << std::string(indent, ' ') << "name: ";
        detail::PrintName(os, reg.GetName());
        os << '\n' << std::string(indent, ' ') << "address: ";
        PrintSExpr(os, reg.GetAddress(), indent);
        os << '\n' << std::string(indent, ' ') << "displacement: ";
        PrintSExpr(os, reg.GetDisp(), indent);
        os << '\n' << std::string(indent, ' ') << "is_external: ";
        PrintSExpr(os, reg.GetIsExternal(), indent);

        os << '\n' << std::string(indent, ' ');
        PrintSExpr(os, reg.GetRetTy(), indent);

        for (const auto& ty : reg.GetArgs()) {
            os << '\n' << std::string(indent, ' ');
            PrintSExpr(os, *ty, indent);
        }

        os << ')';
    }

    void PrintSExpr(auto&& os, const Function& reg, int indent = 0) {
        indent += 4;
        os << "(function\n" << std::string(indent, ' ') << "name: ";
        detail::PrintName(os, reg.GetName());
        os << '\n' << std::string(indent, ' ') << "address: ";
        PrintSExpr(os, reg.GetAddress(), indent);
        os << '\n' << std::string(indent, ' ') << "displacement: ";
        PrintSExpr(os, reg.GetDisp(), indent);
        os << '\n' << std::string(indent, ' ') << "is_external: ";
        PrintSExpr(os, reg.GetIsExternal(), indent);
        for (auto& reg : reg.GetRegions()) {
            os << '\n' << std::string(indent, ' ');
            PrintSExpr(os, reg, indent);
        }
        os << ')';
    }

    void PrintSExpr(auto&& os, const ExternalGlobal& reg, int indent = 0) {
        indent += 4;
        os << "(external_global\n" << std::string(indent, ' ') << "address: ";
        PrintSExpr(os, reg.GetAddress(), indent);
        os << '\n' << std::string(indent, ' ') << "name: ";
        detail::PrintName(os, reg.GetName());
        os << '\n' << std::string(indent, ' ') << "displacement: ";
        PrintSExpr(os, reg.GetDisp(), indent);
        os << '\n' << std::string(indent, ' ') << "is_external: ";
        PrintSExpr(os, reg.GetIsExternal(), indent);
        os << '\n' << std::string(indent, ' ') << "bit_size: ";
        PrintSExpr(os, reg.GetBitSize(), indent);

        os << '\n' << std::string(indent, ' ');
        PrintSExpr(os, reg.GetTy(), indent);

        os << ')';
    }

    void PrintSExpr(auto&& os, const TypeDecl& reg, int indent = 0) {
        indent += 4;
        os << "(type_decl\n" << std::string(indent, ' ');
        detail::PrintName(os, reg.GetName());
        os << '\n' << std::string(indent, ' ');
        PrintSExpr(os, reg.GetTy(), indent);

        os << ')';
    }

    void PrintSExpr(auto&& os, const LangDecl& decl, int indent = 0) {
        std::visit([&os, indent](const auto& decl) { PrintSExpr(os, decl, indent); }, decl);
    }

    void PrintSExpr(auto&& os, const PModule& reg, int indent = 0) {
        indent += 4;
        os << "(module\n";
        os << std::string(indent, ' ') << "layout: ";
        PrintSExpr(os, reg.GetDataLayout(), indent);
        os << '\n' << std::string(indent, ' ') << "triplet: ";
        PrintSExpr(os, reg.GetTargetTriple(), indent);
        os << '\n' << std::string(indent, ' ') << "image_base: ";
        PrintSExpr(os, reg.GetImageBase(), indent);

        for (const auto& x : reg.GetDecls()) {
            os << '\n' << std::string(indent, ' ');
            PrintSExpr(os, x, indent);
        }

        os << ')';
    }

} // namespace irene3::patchlang