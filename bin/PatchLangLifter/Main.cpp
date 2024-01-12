#include <gflags/gflags.h>
#include <glog/logging.h>
#include <iostream>
#include <irene3/PatchIR/PatchIRDialect.h>
#include <irene3/PatchIR/PatchIROps.h>
#include <irene3/PatchLang/Expr.h>
#include <irene3/PatchLang/Exprs.h>
#include <irene3/PatchLang/Lifter.h>
#include <irene3/PatchLang/SExprPrinter.h>
#include <irene3/PatchLang/Stmt.h>
#include <irene3/Util.h>
#include <llvm/Support/raw_ostream.h>
#include <mlir/Dialect/LLVMIR/LLVMDialect.h>
#include <mlir/Dialect/LLVMIR/LLVMTypes.h>
#include <mlir/IR/BuiltinAttributes.h>
#include <mlir/IR/BuiltinOps.h>
#include <mlir/IR/MLIRContext.h>
#include <mlir/Parser/Parser.h>
#include <mlir/Support/LLVM.h>
#include <stdexcept>
#include <string>
#include <vector>
DEFINE_string(mlir_in, "", "MLIR output file");
DEFINE_bool(h, false, "help");
DEFINE_uint64(target_uid, 0, "UID");
DECLARE_bool(help);

int main(int argc, char* argv[]) {
    google::SetUsageMessage("IRENE3 MLIR Lifter");
    google::ParseCommandLineNonHelpFlags(&argc, &argv, false);
    google::InitGoogleLogging(argv[0]);

    if (argc <= 1 || FLAGS_help || FLAGS_h) {
        google::ShowUsageWithFlagsRestrict(argv[0], __FILE__);
        return EXIT_FAILURE;
    }

    mlir::MLIRContext context;
    irene3::PatchIRContext(context);

    mlir::ParserConfig conf(&context, true);
    auto op = mlir::parseSourceFile(FLAGS_mlir_in, conf);

    auto mod = mlir::cast< mlir::ModuleOp >(*op);

    irene3::patchlang::LifterContext lifter(context, mod);

    std::optional< irene3::patchir::FunctionOp > target_function;

    std::vector< irene3::patchlang::LangDecl > decls;

    // Note(Ian): So we need to only lift types that we name here so they need to be added to a
    // mapping
    for (auto glbl : mod.getOps< mlir::LLVM::GlobalOp >()) {
        auto ty = glbl.getGlobalType();
        if (auto sty = mlir::dyn_cast< mlir::LLVM::LLVMStructType >(ty)) {
            if (!sty.getName().empty()) {
                // LOG(FATAL) << "";
                decls.push_back(lifter.AddNamedType(sty.getName().str(), sty));
            }
        }
    }

    for (auto gv_op : mod.getOps< irene3::patchir::Global >()) {
        decls.push_back(lifter.LiftGlobal(gv_op));
    }

    for (auto fop : mod.getOps< irene3::patchir::FunctionOp >()) {
        for (auto rop : fop.getOps< irene3::patchir::RegionOp >()) {
            if (rop.getUid() == FLAGS_target_uid) {
                target_function = fop;
            }
        }
        // A function without a region is an external that we should create a reference for
        // externs are placed before the target so they are in scope.
        if (fop.getRegion().empty() || fop.getBody().getOps().empty()) {
            decls.push_back(lifter.LiftExternal(fop));
        }
    }

    if (!target_function) {
        throw std::runtime_error("UID: " + std::to_string(FLAGS_target_uid) + " not in target");
    }

    auto fop = *target_function;
    irene3::patchlang::IntLitExpr func_addr(
        llvm::APSInt::getUnsigned(fop.getAddress()), irene3::patchlang::LitBase::Hexadecimal, {});
    irene3::patchlang::IntLitExpr func_disp(
        llvm::APSInt::get(fop.getDisp()), irene3::patchlang::LitBase::Decimal, {});
    irene3::patchlang::BoolLitExpr func_ext(fop.getIsExternal(), {});
    std::vector< irene3::patchlang::Region > regs;
    for (auto rop : fop.getOps< irene3::patchir::RegionOp >()) {
        regs.emplace_back(lifter.LiftRegion(rop, rop.getUid() == FLAGS_target_uid));
    }

    irene3::patchlang::Function func(
        std::move(regs), std::move(func_addr), std::move(func_disp), std::move(func_ext),
        fop.getName().str(), {}, {}, {});

    decls.push_back(std::move(func));

    auto target
        = mlir::cast< mlir::StringAttr >(
              mod.getOperation()->getAttr(mlir::LLVM::LLVMDialect::getTargetTripleAttrName()))
              .str();

    auto datalayout
        = mlir::cast< mlir::StringAttr >(
              mod.getOperation()->getAttr(mlir::LLVM::LLVMDialect::getDataLayoutAttrName()))
              .str();

    auto image_base
        = mlir::cast< mlir::IntegerAttr >(
              mod.getOperation()->getAttr(irene3::patchir::PatchIRDialect::getImageBaseAttrName()))
              .getAPSInt();

    irene3::patchlang::PModule pmod(
        irene3::patchlang::StrLitExpr(datalayout, irene3::patchlang::Token()),
        irene3::patchlang::StrLitExpr(target, irene3::patchlang::Token()),
        irene3::patchlang::IntLitExpr(
            image_base, irene3::patchlang::LitBase::Hexadecimal, irene3::patchlang::Token()),
        std::move(decls), irene3::patchlang::Token(), irene3::patchlang::Token());

    irene3::patchlang::PrintSExpr(std::cout, pmod);
}