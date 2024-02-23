#include <gflags/gflags.h>
#include <glog/logging.h>
#include <iostream>
#include <irene3/PatchLang/Lifter.h>
#include <irene3/PatchLang/SExprPrinter.h>
#include <irene3/Util.h>
#include <limits>
#include <mlir/IR/BuiltinOps.h>
#include <mlir/IR/MLIRContext.h>
#include <mlir/Parser/Parser.h>
#include <mlir/Support/LLVM.h>
#include <optional>
#include <string>

static constexpr const uint64_t INVALID_UID = std::numeric_limits< decltype(INVALID_UID) >::max();

DEFINE_string(mlir_in, "", "MLIR output file");
DEFINE_bool(h, false, "help");
DEFINE_uint64(target_uid, INVALID_UID, "UID");
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

    auto uid = FLAGS_target_uid == INVALID_UID ? std::nullopt
                                               : std::optional< uint64_t >(FLAGS_target_uid);

    auto pmod = irene3::patchlang::LiftPatchLangModule(context, mod, uid);

    irene3::patchlang::PrintSExpr(std::cout, pmod);
}
