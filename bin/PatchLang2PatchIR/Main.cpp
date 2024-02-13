#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <iostream>
#include <irene3/PatchIR/PatchIRAttrs.h>
#include <irene3/PatchIR/PatchIRDialect.h>
#include <irene3/PatchIR/PatchIROps.h>
#include <irene3/PatchIR/PatchIRTypes.h>
#include <irene3/PatchLang/Expr.h>
#include <irene3/PatchLang/Exprs.h>
#include <irene3/PatchLang/Lexer.h>
#include <irene3/PatchLang/Location.h>
#include <irene3/PatchLang/Parser.h>
#include <irene3/PatchLang/Stmt.h>
#include <irene3/PatchLang/Types.h>
#include <iterator>
#include <llvm/ADT/APFloat.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/Support/raw_ostream.h>
#include <mlir/Dialect/DLTI/DLTI.h>
#include <mlir/Dialect/LLVMIR/LLVMAttrs.h>
#include <mlir/Dialect/LLVMIR/LLVMDialect.h>
#include <mlir/Dialect/LLVMIR/LLVMTypes.h>
#include <mlir/IR/Attributes.h>
#include <mlir/IR/Builders.h>
#include <mlir/IR/BuiltinAttributes.h>
#include <mlir/IR/BuiltinOps.h>
#include <mlir/IR/BuiltinTypes.h>
#include <mlir/IR/DialectRegistry.h>
#include <mlir/IR/Location.h>
#include <mlir/IR/MLIRContext.h>
#include <mlir/IR/Operation.h>
#include <mlir/IR/OperationSupport.h>
#include <mlir/IR/TypeRange.h>
#include <mlir/IR/Types.h>
#include <mlir/IR/Verifier.h>
#include <mlir/Support/LLVM.h>
#include <mlir/Target/LLVMIR/Import.h>
#include <sstream>
#include <unordered_map>
#include <variant>
#include <vector>

DEFINE_string(input, "", "Input IRENE patch file");
DEFINE_string(output, "", "Output PatchIR file");
DEFINE_bool(print_locs, true, "Print source locations");

std::string read_input_file() {
    if (FLAGS_input.empty()) {
        return std::string(std::istreambuf_iterator< char >(std::cin), {});
    } else {
        std::ifstream input_file(FLAGS_input);
        if (!input_file) {
            LOG(FATAL) << "Couldn't open input file `" << FLAGS_input << '`';
        }
        return std::string(std::istreambuf_iterator< char >(input_file), {});
    }
}

class MLIRCodegen {
    mlir::MLIRContext& mlir_context;
    mlir::OwningOpRef< mlir::ModuleOp > mlir_module;
    mlir::LLVM::LLVMPointerType ptr_type;
    std::unordered_map< std::string, mlir::Type > in_scope_types;
    llvm::DataLayout layout;

    using SymbolMap = std::unordered_map< std::string, mlir::Value >;

    auto StringAttr(const auto& str) { return mlir::StringAttr::get(&mlir_context, str); }

    auto SymbolRefAttr(const auto& str) { return mlir::SymbolRefAttr::get(&mlir_context, str); }

    mlir::Attribute ToValueLocAttr(const irene3::patchlang::RegisterLocation& loc) {
        return irene3::patchir::RegisterAttr::get(
            &mlir_context, StringAttr(loc.GetRegisterName()),
            static_cast< uint64_t >(loc.GetSize()));
    }

    mlir::Attribute ToValueLocAttr(const irene3::patchlang::MemoryLocation& loc) {
        return irene3::patchir::MemoryAttr::get(
            &mlir_context, static_cast< uint64_t >(loc.GetAddress()),
            static_cast< int64_t >(loc.GetDisp()), loc.GetIsExternal().GetValue(),
            static_cast< uint64_t >(loc.GetSize()));
    }

    mlir::Attribute ToValueLocAttr(const irene3::patchlang::IndirectMemoryLocation& loc) {
        return irene3::patchir::MemoryIndirectAttr::get(
            &mlir_context, StringAttr(loc.GetBaseName()), static_cast< int64_t >(loc.GetOffset()),
            static_cast< uint64_t >(loc.GetSize()));
    }

    mlir::Attribute ToValueLocAttr(const irene3::patchlang::Location& loc) {
        return std::visit([this](auto&& l) { return ToValueLocAttr(l); }, loc);
    }

    mlir::LocationAttr ToLocAttr(irene3::patchlang::Token tok) {
        std::string name = FLAGS_input.empty() ? "<stdin>" : FLAGS_input;
        return mlir::FileLineColLoc::get(StringAttr(name), tok.line, tok.col);
    }

    template< typename T >
    mlir::LocationAttr ToLocAttr(const T& t) {
        return ToLocAttr(t.GetFirstToken());
    }

    template< irene3::patchlang::IsExpr T >
    mlir::Value ToLLVM(const T& expr, mlir::OpBuilder& mlir_builder, const SymbolMap& smap) {
        return std::visit(
            [this, &mlir_builder, &smap](const auto& e) {
                return this->ToLLVM(e, mlir_builder, smap);
            },
            expr);
    }

    mlir::Type ToLLVM(const irene3::patchlang::Type& type) {
        return std::visit([this](const auto& t) { return ToLLVM(t); }, type);
    }

    template< irene3::patchlang::IsStmt T >
    void ToLLVM(
        const T& stmt,
        mlir::OpBuilder& mlir_builder,
        SymbolMap& smap,
        mlir::LLVM::LLVMFuncOp& func) {
        std::visit(
            [this, &mlir_builder, &smap, &func](const auto& s) {
                this->ToLLVM(s, mlir_builder, smap, func);
            },
            stmt);
    }

    mlir::Value ToLLVM(
        const irene3::patchlang::AddrOf& lit, mlir::OpBuilder& mlir_builder, const SymbolMap&) {
        return mlir_builder.create< mlir::LLVM::AddressOfOp >(
            ToLocAttr(lit), ptr_type, lit.GetGValue().GetValue());
    }

    mlir::Value ToLLVM(
        const irene3::patchlang::IntLitExpr& lit, mlir::OpBuilder& mlir_builder, const SymbolMap&) {
        auto val  = lit.GetValue();
        auto type = mlir::IntegerType::get(&mlir_context, val.getBitWidth());
        return mlir_builder.create< mlir::LLVM::ConstantOp >(ToLocAttr(lit), type, val);
    }

    static mlir::Type FloatSemaToMLIR(mlir::MLIRContext* ctx, const llvm::fltSemantics& sema) {
        using llvm::APFloatBase;
        using mlir::FloatType;
        switch (APFloatBase::SemanticsToEnum(sema)) {
            case APFloatBase::S_IEEEhalf: return FloatType::getF16(ctx);
            case APFloatBase::S_BFloat: return FloatType::getBF16(ctx);
            case APFloatBase::S_IEEEsingle: return FloatType::getF32(ctx);
            case APFloatBase::S_IEEEdouble: return FloatType::getF64(ctx);
            case APFloatBase::S_IEEEquad: return FloatType::getF128(ctx);
            case APFloatBase::S_Float8E5M2: return FloatType::getFloat8E5M2(ctx);
            case APFloatBase::S_Float8E5M2FNUZ: return FloatType::getFloat8E5M2FNUZ(ctx);
            case APFloatBase::S_Float8E4M3FN: return FloatType::getFloat8E4M3FN(ctx);
            case APFloatBase::S_Float8E4M3FNUZ: return FloatType::getFloat8E4M3FNUZ(ctx);
            case APFloatBase::S_Float8E4M3B11FNUZ: return FloatType::getFloat8E4M3B11FNUZ(ctx);
            case APFloatBase::S_FloatTF32: return FloatType::getTF32(ctx);
            case APFloatBase::S_x87DoubleExtended: return FloatType::getF80(ctx);
            default: LOG(FATAL) << "Unsupported float type"; return nullptr;
        }
    }

    mlir::Value ToLLVM(
        const irene3::patchlang::FloatLitExpr& lit,
        mlir::OpBuilder& mlir_builder,
        const SymbolMap&) {
        auto val  = lit.GetValue();
        auto type = FloatSemaToMLIR(&mlir_context, val.getSemantics());
        return mlir_builder.create< mlir::LLVM::ConstantOp >(ToLocAttr(lit), type, val);
    }

    mlir::Value ToLLVM(
        const irene3::patchlang::SelectExpr& lit,
        mlir::OpBuilder& mlir_builder,
        const SymbolMap& smap) {
        auto cond     = ToLLVM(lit.GetCondition(), mlir_builder, smap);
        auto if_true  = ToLLVM(lit.GetTrueCase(), mlir_builder, smap);
        auto if_false = ToLLVM(lit.GetFalseCase(), mlir_builder, smap);

        return mlir_builder.create< mlir::LLVM::SelectOp >(ToLocAttr(lit), cond, if_true, if_false);
    }

    mlir::Value ToLLVM(
        const irene3::patchlang::BoolLitExpr& lit,
        mlir::OpBuilder& mlir_builder,
        const SymbolMap&) {
        auto type = mlir::IntegerType::get(&mlir_context, 1);
        return mlir_builder.create< mlir::LLVM::ConstantOp >(ToLocAttr(lit), type, lit.GetValue());
    }

    mlir::Value ToLLVM(
        const irene3::patchlang::StrLitExpr& lit, mlir::OpBuilder&, const SymbolMap&) {
        LOG(FATAL) << lit.GetFirstToken().GetPositionString() << ": Invalid string expression";
        return nullptr;
    }

    mlir::Value ToLLVM(
        const irene3::patchlang::DeclRefExpr& ref, mlir::OpBuilder&, const SymbolMap& smap) {
        auto sym = smap.find(ref.GetName());
        if (sym == smap.end()) {
            LOG(FATAL) << ref.GetFirstToken().GetPositionString() << ": Unknown symbol name `"
                       << ref.GetName() << '`';
            return nullptr;
        }

        return sym->second;
    }

    mlir::Value ToLLVM(
        const irene3::patchlang::BinaryExpr& expr,
        mlir::OpBuilder& mlir_builder,
        const SymbolMap& smap) {
        auto lhs = ToLLVM(expr.GetLHS(), mlir_builder, smap);
        auto rhs = ToLLVM(expr.GetRHS(), mlir_builder, smap);
        auto loc = ToLocAttr(expr.GetFirstToken());

        using enum irene3::patchlang::BinaryOp;

        // TODO(frabert): Handle nuw nsw
        if ((expr.GetOp() & irene3::patchlang::OP_MASK) == Add) {
            return mlir_builder.create< mlir::LLVM::AddOp >(loc, lhs, rhs);
        } else if ((expr.GetOp() & irene3::patchlang::OP_MASK) == Sub) {
            return mlir_builder.create< mlir::LLVM::SubOp >(loc, lhs, rhs);
        } else if ((expr.GetOp() & irene3::patchlang::OP_MASK) == Mul) {
            return mlir_builder.create< mlir::LLVM::MulOp >(loc, lhs, rhs);
        } else if ((expr.GetOp() & irene3::patchlang::OP_MASK) == Shl) {
            return mlir_builder.create< mlir::LLVM::ShlOp >(loc, lhs, rhs);
        }

        mlir::LLVM::ICmpPredicate icmp_pred;

        switch (expr.GetOp()) {
            default:
                LOG(FATAL) << expr.GetFirstToken().GetPositionString() << ": Invalid operation";
                return nullptr;
            case Fadd: return mlir_builder.create< mlir::LLVM::FAddOp >(loc, lhs, rhs);
            case Fsub: return mlir_builder.create< mlir::LLVM::FSubOp >(loc, lhs, rhs);
            case Fmul: return mlir_builder.create< mlir::LLVM::FMulOp >(loc, lhs, rhs);
            case Udiv: return mlir_builder.create< mlir::LLVM::UDivOp >(loc, lhs, rhs);
            case Sdiv: return mlir_builder.create< mlir::LLVM::SDivOp >(loc, lhs, rhs);
            case Fdiv: return mlir_builder.create< mlir::LLVM::FDivOp >(loc, lhs, rhs);
            case Srem: return mlir_builder.create< mlir::LLVM::SRemOp >(loc, lhs, rhs);
            case Frem: return mlir_builder.create< mlir::LLVM::FRemOp >(loc, lhs, rhs);
            case Lshr: return mlir_builder.create< mlir::LLVM::LShrOp >(loc, lhs, rhs);
            case Ashr: return mlir_builder.create< mlir::LLVM::AShrOp >(loc, lhs, rhs);
            case And: return mlir_builder.create< mlir::LLVM::AndOp >(loc, lhs, rhs);
            case Or: return mlir_builder.create< mlir::LLVM::OrOp >(loc, lhs, rhs);
            case Xor: return mlir_builder.create< mlir::LLVM::XOrOp >(loc, lhs, rhs);

            case Eq:
                icmp_pred = mlir::LLVM::ICmpPredicate::eq;
                return mlir_builder.create< mlir::LLVM::ICmpOp >(loc, icmp_pred, lhs, rhs);
            case Ne:
                icmp_pred = mlir::LLVM::ICmpPredicate::ne;
                return mlir_builder.create< mlir::LLVM::ICmpOp >(loc, icmp_pred, lhs, rhs);
            case Ugt:
                icmp_pred = mlir::LLVM::ICmpPredicate::ugt;
                return mlir_builder.create< mlir::LLVM::ICmpOp >(loc, icmp_pred, lhs, rhs);
            case Uge:
                icmp_pred = mlir::LLVM::ICmpPredicate::uge;
                return mlir_builder.create< mlir::LLVM::ICmpOp >(loc, icmp_pred, lhs, rhs);
            case Ult:
                icmp_pred = mlir::LLVM::ICmpPredicate::ult;
                return mlir_builder.create< mlir::LLVM::ICmpOp >(loc, icmp_pred, lhs, rhs);
            case Ule:
                icmp_pred = mlir::LLVM::ICmpPredicate::ule;
                return mlir_builder.create< mlir::LLVM::ICmpOp >(loc, icmp_pred, lhs, rhs);
            case Sgt:
                icmp_pred = mlir::LLVM::ICmpPredicate::sgt;
                return mlir_builder.create< mlir::LLVM::ICmpOp >(loc, icmp_pred, lhs, rhs);
            case Sge:
                icmp_pred = mlir::LLVM::ICmpPredicate::sge;
                return mlir_builder.create< mlir::LLVM::ICmpOp >(loc, icmp_pred, lhs, rhs);
            case Slt:
                icmp_pred = mlir::LLVM::ICmpPredicate::slt;
                return mlir_builder.create< mlir::LLVM::ICmpOp >(loc, icmp_pred, lhs, rhs);
            case Sle:
                icmp_pred = mlir::LLVM::ICmpPredicate::sle;
                return mlir_builder.create< mlir::LLVM::ICmpOp >(loc, icmp_pred, lhs, rhs);
        }
    }

    mlir::Value ToLLVM(
        const irene3::patchlang::UnaryExpr& lit, mlir::OpBuilder&, const SymbolMap&) {
        LOG(FATAL) << lit.GetFirstToken().GetPositionString() << ": Not implemented yet";
        return nullptr;
    }

    mlir::Value ToLLVM(
        const irene3::patchlang::GetElementPtrExpr& expr,
        mlir::OpBuilder& mlir_builder,
        const SymbolMap& smap) {
        auto type = ToLLVM(expr.ElementType());
        std::vector< mlir::Value > indices;
        std::transform(
            expr.GetIndices().begin(), expr.GetIndices().end(), std::back_inserter(indices),
            [this, &mlir_builder, &smap](const irene3::patchlang::ExprPtr& e) {
                return ToLLVM(*e, mlir_builder, smap);
            });
        auto base = ToLLVM(expr.GetBase(), mlir_builder, smap);
        return mlir_builder.create< mlir::LLVM::GEPOp >(
            ToLocAttr(expr), ptr_type, type, base, indices);
    }

    mlir::Value ToLLVM(
        const irene3::patchlang::CallExpr& expr, mlir::OpBuilder& bldr, const SymbolMap& smap) {
        auto callee = expr.GetCallee();
        std::vector< mlir::Value > args;
        for (const auto& arg : expr.GetArgs()) {
            mlir::Value expr = ToLLVM(*arg, bldr, smap);
            args.push_back(expr);
        }

        auto function
            = this->mlir_module->lookupSymbol< mlir::LLVM::LLVMFuncOp >(callee.GetValue());

        if (!function) {
            LOG(FATAL) << "Call to undefined symbol: " << callee.GetValue();
        }

        mlir::LLVM::CallOp cop = bldr.create< mlir::LLVM::CallOp >(
            ToLocAttr(expr), function.getFunctionType().getReturnType(), callee.GetValue(), args);

        if (cop.getResult()) {
            return cop.getResult();
        } else {
            return mlir::Value();
        }
    }

    mlir::Value ToLLVM(
        const irene3::patchlang::CallIntrinsicExpr& expr,
        mlir::OpBuilder& bldr,
        const SymbolMap& smap) {
        auto callee = expr.GetCallee();
        std::vector< mlir::Value > args;
        for (const auto& arg : expr.GetArgs()) {
            mlir::Value expr = ToLLVM(*arg, bldr, smap);
            args.push_back(expr);
        }

        auto function
            = this->mlir_module->lookupSymbol< mlir::LLVM::LLVMFuncOp >(callee.GetValue());

        if (!function) {
            LOG(FATAL) << "Call to undefined symbol: " << callee.GetValue();
        }

        mlir::LLVM::CallIntrinsicOp cop = bldr.create< mlir::LLVM::CallIntrinsicOp >(
            ToLocAttr(expr), function.getFunctionType().getReturnType(), callee.GetValue(), args,
            mlir::LLVM::FastmathFlags::none);

        auto results = cop->getResults();
        CHECK(results.size() <= 1) << "Too many results for intrinsic";

        if (results.size() == 1) {
            return cop.getResult(0);
        } else {
            return mlir::Value();
        }
    }

    mlir::Value ToLLVM(
        const irene3::patchlang::AllocaExpr& expr,
        mlir::OpBuilder& mlir_builder,
        const SymbolMap& smap) {
        auto arraySize = ToLLVM(expr.GetArraySize(), mlir_builder, smap);
        auto type      = ToLLVM(expr.GetType());
        return mlir_builder.create< mlir::LLVM::AllocaOp >(
            ToLocAttr(expr), ptr_type, type, arraySize,
            expr.GetAlignment().GetValue().getZExtValue());
    }

    mlir::Value ToLLVM(
        const irene3::patchlang::LoadExpr& expr,
        mlir::OpBuilder& mlir_builder,
        const SymbolMap& smap) {
        auto type     = ToLLVM(expr.GetType());
        auto sub_expr = ToLLVM(expr.GetPointer(), mlir_builder, smap);
        return mlir_builder.create< mlir::LLVM::LoadOp >(
            ToLocAttr(expr), type, sub_expr, 0, expr.GetIsVolatile());
    }

    mlir::Value ToLLVM(
        const irene3::patchlang::NullExpr& expr, mlir::OpBuilder& mlir_builder, const SymbolMap&) {
        return mlir_builder.create< mlir::LLVM::NullOp >(ToLocAttr(expr), ptr_type);
    }

    mlir::Value ToLLVM(
        const irene3::patchlang::CastExpr& expr,
        mlir::OpBuilder& mlir_builder,
        const SymbolMap& smap) {
        auto target_type = ToLLVM(expr.GetType());
        auto sub_expr    = ToLLVM(expr.GetValue(), mlir_builder, smap);
        auto loc         = ToLocAttr(expr);

        using enum irene3::patchlang::CastExprKind;
        switch (expr.GetKind()) {
            case Trunc:
                return mlir_builder.create< mlir::LLVM::TruncOp >(loc, target_type, sub_expr);
            case ZExt: return mlir_builder.create< mlir::LLVM::ZExtOp >(loc, target_type, sub_expr);
            case SExt: return mlir_builder.create< mlir::LLVM::SExtOp >(loc, target_type, sub_expr);
            case FPTrunc:
                return mlir_builder.create< mlir::LLVM::FPTruncOp >(loc, target_type, sub_expr);
            case FPExt:
                return mlir_builder.create< mlir::LLVM::FPExtOp >(loc, target_type, sub_expr);
            case FPToUI:
                return mlir_builder.create< mlir::LLVM::FPToUIOp >(loc, target_type, sub_expr);
            case FPToSI:
                return mlir_builder.create< mlir::LLVM::FPToSIOp >(loc, target_type, sub_expr);
            case UIToFP:
                return mlir_builder.create< mlir::LLVM::UIToFPOp >(loc, target_type, sub_expr);
            case SIToFP:
                return mlir_builder.create< mlir::LLVM::SIToFPOp >(loc, target_type, sub_expr);
            case PtrToInt:
                return mlir_builder.create< mlir::LLVM::PtrToIntOp >(loc, target_type, sub_expr);
            case IntToPtr:
                return mlir_builder.create< mlir::LLVM::IntToPtrOp >(loc, target_type, sub_expr);
            case BitCast:
                return mlir_builder.create< mlir::LLVM::BitcastOp >(loc, target_type, sub_expr);
        }
        LOG(FATAL) << "Reached the unreachable";
        return nullptr;
    }

    void convertRegion(
        uint64_t func_addr, const irene3::patchlang::Region& region, mlir::Block& block) {
        mlir::OpBuilder region_builder(&mlir_context);
        mlir::OpBuilder func_builder(&mlir_context);

        region_builder.setInsertionPointToEnd(&block);
        auto region_op = region_builder.create< irene3::patchir::RegionOp >(
            ToLocAttr(region.GetFirstToken()), static_cast< uint64_t >(region.GetAddress()),
            static_cast< uint64_t >(region.GetUID()), static_cast< uint64_t >(region.GetSize()),
            static_cast< int64_t >(region.GetStackOffsetAtEntry()),
            static_cast< int64_t >(region.GetStackOffsetAtExit()));
        region_builder.setInsertionPointToEnd(&region_op.getBody().emplaceBlock());

        std::vector< mlir::Value > values;
        for (auto& stmt : region.GetBody()) {
            if (std::holds_alternative< irene3::patchlang::ValueStmt >(stmt)) {
                auto& value              = std::get< irene3::patchlang::ValueStmt >(stmt);
                auto entry_loc           = value.GetLocationAtEntry();
                auto exit_loc            = value.GetLocationAtExit();
                mlir::Attribute at_entry = entry_loc ? ToValueLocAttr(entry_loc.value()) : nullptr;
                mlir::Attribute at_exit  = exit_loc ? ToValueLocAttr(exit_loc.value()) : nullptr;

                auto elem_ty = this->ToLLVM(value.GetValueType());

                auto lptr_ty
                    = irene3::patchir::LowValuePointerType::get(&this->mlir_context, elem_ty);

                auto value_op = region_builder.create< irene3::patchir::ValueOp >(
                    ToLocAttr(value), lptr_ty, StringAttr(value.GetName()), at_entry, at_exit);
                values.push_back(value_op);
            }
        }

        auto llvm_func_name
            = (std::stringstream() << "func" << func_addr << "basic_block"
                                   << static_cast< uint64_t >(region.GetAddress()) << "_"
                                   << static_cast< uint64_t >(region.GetUID()))
                  .str();
        region_builder.create< irene3::patchir::CallOp >(
            region_builder.getUnknownLoc(), SymbolRefAttr(llvm_func_name), values);
    }

    mlir::Type ToLLVM(const irene3::patchlang::PrimitiveType& type) {
        if (type.GetName() == "i8") {
            return mlir::IntegerType::get(&mlir_context, 8);
        } else if (type.GetName() == "i16") {
            return mlir::IntegerType::get(&mlir_context, 16);
        } else if (type.GetName() == "i32") {
            return mlir::IntegerType::get(&mlir_context, 32);
        } else if (type.GetName() == "i64") {
            return mlir::IntegerType::get(&mlir_context, 64);
        } else if (type.GetName() == "i128") {
            return mlir::IntegerType::get(&mlir_context, 128);
        } else if (type.GetName() == "f32") {
            return mlir::Float32Type::get(&mlir_context);
        } else if (type.GetName() == "f64") {
            return mlir::Float64Type::get(&mlir_context);
        } else if (type.GetName() == "ptr") {
            return ptr_type;
        } else if (type.GetName() == "void") {
            return mlir::LLVM::LLVMVoidType::get(&mlir_context);
        } else {
            if (this->in_scope_types.find(type.GetName()) != this->in_scope_types.end()) {
                return this->in_scope_types.at(type.GetName());
            }

            LOG(FATAL) << type.GetNameToken().GetPositionString() << ": Unknown primitive type `"
                       << type.GetName() << '`';
        }
    }

    mlir::Type ToLLVM(const irene3::patchlang::StructType& type) {
        std::vector< mlir::Type > body;
        std::transform(
            type.GetElements().begin(), type.GetElements().end(), std::back_inserter(body),
            [this](const irene3::patchlang::TypePtr& t) { return ToLLVM(*t); });
        return mlir::LLVM::LLVMStructType::getLiteral(&mlir_context, body);
    }

    mlir::Type ToLLVM(const irene3::patchlang::ArrayType& type) {
        auto elem_type = ToLLVM(type.GetType());
        return mlir::LLVM::LLVMArrayType::get(elem_type, static_cast< uint64_t >(type.GetSize()));
    }

    mlir::Type ToLLVM(const irene3::patchlang::VectorType& type) {
        LOG(FATAL) << "Not implemented yet";
        return nullptr;
    }

    void ToLLVM(
        const irene3::patchlang::NopStmt&, mlir::OpBuilder&, SymbolMap&, mlir::LLVM::LLVMFuncOp&) {
        // Nothing to emit
    }

    void ToLLVM(
        const irene3::patchlang::LetDeclStmt& stmt,
        mlir::OpBuilder& mlir_builder,
        SymbolMap& smap,
        mlir::LLVM::LLVMFuncOp&) {
        auto& name = stmt.GetName();
        if (smap.contains(name)) {
            LOG(FATAL) << stmt.GetFirstToken().GetPositionString() << ": Symbol `" << name
                       << "` already exists";
        }

        smap[name] = ToLLVM(stmt.GetExpr(), mlir_builder, smap);
    }

    mlir::LLVM::ConstantOp BuildAddr(
        mlir::OpBuilder& mlir_builder,
        const irene3::patchlang::IntLitExpr& addr,
        mlir::LLVM::LLVMFuncOp& func) {
        auto iptr
            = mlir::IntegerType::get(&this->mlir_context, this->layout.getPointerSizeInBits());
        return mlir_builder.create< mlir::LLVM::ConstantOp >(
            ToLocAttr(addr),
            mlir::IntegerAttr::get(iptr, addr.GetValue().zextOrTrunc(iptr.getWidth())));
    }

    void ToLLVM(
        const irene3::patchlang::ConditionalGotoStmt& stmt,
        mlir::OpBuilder& mlir_builder,
        SymbolMap& smap,
        mlir::LLVM::LLVMFuncOp& func) {
        auto loc = ToLocAttr(stmt);

        auto cond = ToLLVM(stmt.GetCond(), mlir_builder, smap);

        auto jump_block     = func.addBlock();
        auto continue_block = func.addBlock();

        mlir_builder.create< mlir::LLVM::CondBrOp >(loc, cond, jump_block, continue_block);

        mlir::OpBuilder jmpbldr(jump_block, jump_block->begin());
        std::vector< mlir::Value > args{ BuildAddr(jmpbldr, stmt.GetTarget(), func) };
        jmpbldr.create< mlir::LLVM::CallOp >(
            loc, std::nullopt, SymbolRefAttr("__anvill_goto"), args);
        jmpbldr.create< mlir::LLVM::UnreachableOp >(loc);

        mlir_builder.setInsertionPoint(continue_block, continue_block->begin());
    }

    void ToLLVM(
        const irene3::patchlang::GotoStmt& stmt,
        mlir::OpBuilder& mlir_builder,
        SymbolMap& smap,
        mlir::LLVM::LLVMFuncOp& func) {
        auto loc = ToLocAttr(stmt);
        std::vector< mlir::Value > args{ BuildAddr(mlir_builder, stmt.GetTarget(), func) };
        mlir_builder.create< mlir::LLVM::CallOp >(
            loc, std::nullopt, SymbolRefAttr("__anvill_goto"), args);
        mlir_builder.create< mlir::LLVM::UnreachableOp >(loc);
    }

    void ToLLVM(
        const irene3::patchlang::StoreStmt& stmt,
        mlir::OpBuilder& mlir_builder,
        SymbolMap& smap,
        mlir::LLVM::LLVMFuncOp&) {
        auto dest  = ToLLVM(stmt.GetDestination(), mlir_builder, smap);
        auto value = ToLLVM(stmt.GetValue(), mlir_builder, smap);

        mlir_builder.create< mlir::LLVM::StoreOp >(
            ToLocAttr(stmt), value, dest, 0, stmt.GetIsVolatile());
    }

    void ToLLVM(
        const irene3::patchlang::ReturnStmt& stmt,
        mlir::OpBuilder& mlir_builder,
        SymbolMap& smap,
        mlir::LLVM::LLVMFuncOp&) {}

    void ToLLVM(
        const irene3::patchlang::CallStmt& stmt,
        mlir::OpBuilder& mlir_builder,
        SymbolMap& smap,
        mlir::LLVM::LLVMFuncOp&) {}

    void ToLLVM(
        const irene3::patchlang::CallIntrinsicStmt& stmt,
        mlir::OpBuilder& mlir_builder,
        SymbolMap& smap,
        mlir::LLVM::LLVMFuncOp&) {}

    void ToLLVM(
        const irene3::patchlang::ValueStmt& stmt,
        mlir::OpBuilder& mlir_builder,
        SymbolMap& smap,
        mlir::LLVM::LLVMFuncOp& func) {
        auto name = std::string(stmt.GetName());
        if (smap.contains(name)) {
            LOG(FATAL) << stmt.GetFirstToken().GetPositionString() << ": Symbol `" << name
                       << "` already exists";
        }

        smap[name] = func.getFunctionBody().addArgument(ptr_type, ToLocAttr(stmt));
    }

  public:
    MLIRCodegen(
        mlir::MLIRContext& mlir_context,
        const std::string& target,
        const std::string& layout,
        uint64_t image_base)
        : mlir_context(mlir_context)
        , ptr_type(mlir::LLVM::LLVMPointerType::get(&mlir_context))
        , layout(layout) {
        std::string name = FLAGS_input.empty() ? "<stdin>" : FLAGS_input;
        auto loc         = mlir::NameLoc::get(StringAttr(name));
        mlir_module      = mlir::ModuleOp::create(loc);

        mlir_module->getOperation()->setAttr(
            mlir::LLVM::LLVMDialect::getDataLayoutAttrName(),
            mlir::StringAttr::get(&mlir_context, layout));
        mlir_module->getOperation()->setAttr(
            mlir::LLVM::LLVMDialect::getTargetTripleAttrName(),
            mlir::StringAttr::get(&mlir_context, target));

        mlir::OpBuilder mlir_builder(&mlir_context);
        mlir_builder.setInsertionPointToEnd(mlir_module->getBody());

        auto addr_ty = mlir::IntegerType::get(
            &mlir_context, llvm::DataLayout(layout).getPointerSizeInBits(),
            mlir::IntegerType::Unsigned);

        mlir_module->getOperation()->setAttr(
            irene3::patchir::PatchIRDialect::getImageBaseAttrName(),
            mlir::IntegerAttr::get(addr_ty, image_base));

        auto goto_type = mlir::LLVM::LLVMFunctionType::get(
            mlir::LLVM::LLVMVoidType::get(&this->mlir_context),
            { mlir::IntegerType::get(
                &mlir_context, llvm::DataLayout(layout).getPointerSizeInBits()) });
        auto anvill_goto = mlir_builder.create< mlir::LLVM::LLVMFuncOp >(
            mlir_builder.getUnknownLoc(), StringAttr("__anvill_goto"), goto_type);
        anvill_goto.setPassthroughAttr(mlir::ArrayAttr::get(&mlir_context, StringAttr("noreturn")));
    }

    void convertTypeDecl(const irene3::patchlang::TypeDecl& decl) {
        auto ty = ToLLVM(decl.GetTy());

        if (mlir::LLVM::LLVMStructType sty = mlir::dyn_cast< mlir::LLVM::LLVMStructType >(ty)) {
            ty = mlir::LLVM::LLVMStructType::getNewIdentified(
                &this->mlir_context, decl.GetName(), sty.getBody(), sty.isPacked());
        }

        this->in_scope_types.insert({ decl.GetName(), ty });
    }

    void convertExternalGlobal(const irene3::patchlang::ExternalGlobal& external) {
        mlir::OpBuilder mlir_builder(&mlir_context);
        mlir_builder.setInsertionPointToEnd(mlir_module->getBody());
        auto loc = ToLocAttr(external);

        auto resty = ToLLVM(external.GetTy());

        auto memattr = irene3::patchir::MemoryAttr::get(
            &mlir_context, static_cast< uint64_t >(external.GetAddress()),
            static_cast< uint64_t >(external.GetDisp()), external.GetIsExternal().GetValue(),
            static_cast< uint64_t >(external.GetBitSize()));

        auto ext_name = StringAttr(external.GetName());
        mlir_builder.create< irene3::patchir::Global >(
            loc, ext_name, mlir::StringAttr(), memattr, resty);

        auto fop = mlir_builder.create< mlir::LLVM::GlobalOp >(
            loc, resty, false, mlir::LLVM::linkage::Linkage::External, external.GetName(),
            mlir::Attribute());

        fop->dump();
    }

    void convertExternal(const irene3::patchlang::External& external) {
        mlir::OpBuilder mlir_builder(&mlir_context);
        mlir_builder.setInsertionPointToEnd(mlir_module->getBody());
        auto loc = ToLocAttr(external);
        mlir_builder.create< irene3::patchir::FunctionOp >(
            loc, static_cast< uint64_t >(external.GetAddress()),
            static_cast< uint64_t >(external.GetDisp()), external.GetIsExternal().GetValue(),
            StringAttr(external.GetName()));

        auto resty = ToLLVM(external.GetRetTy());
        std::vector< mlir::Type > args;
        for (const auto& arg : external.GetArgs()) {
            args.push_back(ToLLVM(*arg));
        }

        auto fty = mlir::LLVM::LLVMFunctionType::get(resty, args);

        mlir_builder.create< mlir::LLVM::LLVMFuncOp >(loc, StringAttr(external.GetName()), fty);
    }

    void convertFunction(const irene3::patchlang::Function& function) {
        mlir::OpBuilder mlir_builder(&mlir_context);
        mlir_builder.setInsertionPointToEnd(mlir_module->getBody());
        auto loc = ToLocAttr(function);

        // TODO(Ian): Why do we do this, dont functions already have names?
        std::string func_name
            = "func" + std::to_string(static_cast< uint64_t >(function.GetAddress()));

        auto funcop = mlir_builder.create< irene3::patchir::FunctionOp >(
            loc, static_cast< uint64_t >(function.GetAddress()),
            static_cast< uint64_t >(function.GetDisp()), function.GetIsExternal().GetValue(),
            StringAttr(func_name));
        auto& funcbody = funcop.getBody().emplaceBlock();
        for (const auto& region : function.GetRegions()) {
            convertRegion(static_cast< uint64_t >(function.GetAddress()), region, funcbody);
            std::vector< mlir::Type > func_args;
            for (auto& stmt : region.GetBody()) {
                if (std::holds_alternative< irene3::patchlang::ValueStmt >(stmt)) {
                    func_args.push_back(ptr_type);
                }
            }

            auto has_non_valuestmt = false;
            for (auto& stmt : region.GetBody()) {
                has_non_valuestmt |= !std::holds_alternative< irene3::patchlang::ValueStmt >(stmt);
            }

            auto llvm_func_type = mlir::LLVM::LLVMFunctionType::get(
                mlir::LLVM::LLVMVoidType::get(&mlir_context), func_args);
            mlir_builder.setInsertionPointToEnd(mlir_module->getBody());
            auto llvm_func = mlir_builder.create< mlir::LLVM::LLVMFuncOp >(
                loc,
                StringAttr(
                    func_name + "basic_block"
                    + std::to_string(static_cast< uint64_t >(region.GetAddress())) + "_"
                    + std::to_string(static_cast< uint64_t >(region.GetUID()))),
                llvm_func_type);
            if (has_non_valuestmt) {
                SymbolMap smap;
                auto& llvm_funcbody = llvm_func.getFunctionBody().emplaceBlock();
                mlir_builder.setInsertionPointToEnd(&llvm_funcbody);
                for (auto& stmt : region.GetBody()) {
                    ToLLVM(stmt, mlir_builder, smap, llvm_func);
                }
            }
        }
    }

    mlir::OwningOpRef< mlir::ModuleOp > GetMLIRModule() { return std::move(mlir_module); }
};

int main(int argc, char* argv[]) {
    google::SetUsageMessage("IRENE3 decompiler");
    google::ParseCommandLineNonHelpFlags(&argc, &argv, false);
    google::InitGoogleLogging(argv[0]);

    auto source = read_input_file();
    irene3::patchlang::Parser parser(irene3::patchlang::Lex(source));
    auto pmod = parser.ParseModule();
    if (!pmod.Succeeded()) {
        LOG(FATAL) << "Syntax error: " << pmod.TakeError();
    }

    mlir::MLIRContext mlir_context;
    mlir_context.getOrLoadDialect< irene3::patchir::PatchIRDialect >();
    mlir_context.getOrLoadDialect< mlir::LLVM::LLVMDialect >();
    mlir_context.getOrLoadDialect< mlir::DLTIDialect >();

    MLIRCodegen codegen(
        mlir_context, pmod.Value().GetTargetTriple().GetValue(),
        pmod.Value().GetDataLayout().GetValue(), pmod->GetImageBase().GetValue().getLimitedValue());

    for (const auto& func : pmod.Value().GetDecls()) {
        if (std::holds_alternative< irene3::patchlang::Function >(func)) {
            codegen.convertFunction(std::get< irene3::patchlang::Function >(func));
        } else if (std::holds_alternative< irene3::patchlang::External >(func)) {
            codegen.convertExternal(std::get< irene3::patchlang::External >(func));
        } else if (std::holds_alternative< irene3::patchlang::ExternalGlobal >(func)) {
            codegen.convertExternalGlobal(std::get< irene3::patchlang::ExternalGlobal >(func));
        } else {
            auto& ty = std::get< irene3::patchlang::TypeDecl >(func);
            codegen.convertTypeDecl(ty);
        }
    }

    auto mlir_module = codegen.GetMLIRModule();
    CHECK(mlir_module->verify().succeeded());

    mlir::OpPrintingFlags printing_flags;
    if (FLAGS_print_locs) {
        printing_flags.enableDebugInfo();
    }

    if (FLAGS_output.empty()) {
        mlir_module->print(llvm::outs(), printing_flags);
    } else {
        std::error_code ec;
        llvm::raw_fd_ostream os(FLAGS_output, ec);
        CHECK(!ec) << "Couldn't open output file `" << FLAGS_output << '`';
        mlir_module->print(os, printing_flags);
    }
}