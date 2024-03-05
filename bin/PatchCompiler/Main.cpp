#include <cstdlib>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <irene3/PatchCompiler.h>
#include <irene3/PatchIR/PatchIRAttrs.h>
#include <irene3/PatchIR/PatchIRDialect.h>
#include <irene3/PatchIR/PatchIROps.h>
#include <irene3/TypeDecoder.h>
#include <irene3/Util.h>
#include <llvm/Passes/OptimizationLevel.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/CodeGen.h>
#include <llvm/Support/JSON.h>
#include <mlir/Dialect/DLTI/DLTI.h>
#include <mlir/Dialect/LLVMIR/LLVMAttrs.h>
#include <mlir/Dialect/LLVMIR/LLVMDialect.h>
#include <mlir/IR/AsmState.h>
#include <mlir/IR/Attributes.h>
#include <mlir/IR/Builders.h>
#include <mlir/IR/BuiltinAttributes.h>
#include <mlir/IR/BuiltinOps.h>
#include <mlir/IR/BuiltinTypes.h>
#include <mlir/IR/DialectRegistry.h>
#include <mlir/IR/MLIRContext.h>
#include <mlir/IR/OpImplementation.h>
#include <mlir/IR/OperationSupport.h>
#include <mlir/IR/Verifier.h>
#include <mlir/Parser/Parser.h>
#include <mlir/Target/LLVMIR/Dialect/Builtin/BuiltinToLLVMIRTranslation.h>
#include <mlir/Target/LLVMIR/Dialect/LLVMIR/LLVMToLLVMIRTranslation.h>
#include <mlir/Target/LLVMIR/Import.h>
#include <optional>
#include <remill/BC/Error.h>

DECLARE_bool(help);

DEFINE_string(patch_def, "", "The mlir file containing the patch definition");
DEFINE_uint64(region_uid, 0, "The target region");
DEFINE_string(out, "", "Output .s file");
DEFINE_string(features, "", "Target feature list (comma separated)");
DEFINE_string(cpu, "", "LLVM CPU Profile");
DEFINE_string(backend, "", "Which compilation backend to use defaults to generic");
DEFINE_string(
    json_metadata, "", "Where to write additional patch data required for patch situation");
DEFINE_bool(opt_space, false, "enable space optimiation");

int main(int argc, char* argv[]) {
    google::SetUsageMessage("IRENE3 decompiler");
    google::ParseCommandLineNonHelpFlags(&argc, &argv, false);

    if (argc <= 1 || FLAGS_help) {
        google::ShowUsageWithFlagsRestrict(argv[0], __FILE__);
        return EXIT_FAILURE;
    }

    if (FLAGS_out.empty()) {
        std::cerr << "Output should be non empty";
        return EXIT_FAILURE;
    }

    google::InitGoogleLogging(argv[0]);

    mlir::MLIRContext mlir_context;
    mlir::DialectRegistry registry;
    registry.insert< irene3::patchir::PatchIRDialect >();
    registry.insert< mlir::LLVM::LLVMDialect >();
    registry.insert< mlir::DLTIDialect >();

    mlir::registerBuiltinDialectTranslation(mlir_context);
    mlir::registerLLVMDialectTranslation(mlir_context);

    mlir_context.appendDialectRegistry(registry);
    mlir::ParserConfig conf(&mlir_context, true);
    auto op = mlir::parseSourceFile(FLAGS_patch_def, conf);

    std::optional< irene3::patchir::RegionOp > region;
    if (auto mod = llvm::dyn_cast< mlir::ModuleOp >(op.get())) {
        // mod->dump();

        for (const auto& op : mod.getBodyRegion().getOps()) {
            if (auto fop = llvm::dyn_cast< irene3::patchir::FunctionOp >(op)) {
                for (irene3::patchir::RegionOp reg : fop.getOps< irene3::patchir::RegionOp >()) {
                    if (reg.getUid() == FLAGS_region_uid) {
                        region = reg;
                    }
                }
            }
        }
    }
    CHECK(region);
    irene3::PatchCompiler comp(
        mlir_context, FLAGS_features, FLAGS_cpu,
        FLAGS_backend.empty() ? std::nullopt : std::optional< std::string >(FLAGS_backend),
        FLAGS_opt_space ? llvm::OptimizationLevel::Os : llvm::OptimizationLevel::O3,
        FLAGS_opt_space ? llvm::CodeGenOpt::Level::Default : llvm::CodeGenOpt::Level::Aggressive);

    std::error_code ec;
    llvm::raw_fd_ostream os(FLAGS_out, ec);
    CHECK(!ec) << "Couldn't open output file `" << FLAGS_out;
    auto res = comp.Compile(*region, os);

    llvm::raw_fd_ostream json_out(FLAGS_json_metadata, ec);
    CHECK(!ec) << "Couldn't open json output file `" << FLAGS_json_metadata;
    llvm::json::OStream jstream(json_out, 4);

    jstream.objectBegin();
    jstream.attribute("patch_offset_from_base", res.patch_offset);
    if (res.image_base_reg) {
        jstream.attribute("base_register", *res.image_base_reg);
    }

    jstream.attributeBegin("free_regs");
    jstream.arrayBegin();
    for (auto r : res.free_regs) {
        jstream.value(r);
    }

    jstream.arrayEnd();
    jstream.attributeEnd();

    jstream.objectEnd();
    jstream.flush();
    json_out.close();
}