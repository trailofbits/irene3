#include <cstdlib>
#include <fstream>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <irene3/PatchIR/PatchIRDialect.h>
#include <irene3/PatchIRCodegen.h>
#include <irene3/Version.h>
#include <llvm/Support/raw_ostream.h>
#include <mlir/Dialect/DLTI/DLTI.h>
#include <mlir/Dialect/LLVMIR/LLVMDialect.h>
#include <mlir/IR/BuiltinOps.h>
#include <mlir/IR/DialectRegistry.h>
#include <mlir/IR/MLIRContext.h>
#include <string>
#include <unordered_set>

DEFINE_string(spec, "", "input spec");
DEFINE_string(mlir_out, "", "MLIR output file");
DEFINE_string(lift_list, "", "list of entities to lift");
DEFINE_bool(h, false, "help");

DECLARE_bool(version);
DECLARE_bool(help);

static void SetVersion(void) {
    std::stringstream version;

    auto vs = irene3::Version::GetVersionString();
    if (0 == vs.size()) {
        vs = "unknown";
    }
    version << vs << "\n";
    if (!irene3::Version::HasVersionData()) {
        version << "No extended version information found!\n";
    } else {
        version << "Commit Hash: " << irene3::Version::GetCommitHash() << "\n";
        version << "Commit Date: " << irene3::Version::GetCommitDate() << "\n";
        version << "Last commit by: " << irene3::Version::GetAuthorName() << " ["
                << irene3::Version::GetAuthorEmail() << "]\n";
        version << "Commit Subject: [" << irene3::Version::GetCommitSubject() << "]\n";
        version << "\n";
        if (irene3::Version::HasUncommittedChanges()) {
            version << "Uncommitted changes were present during build.\n";
        } else {
            version << "All changes were committed prior to building.\n";
        }
    }
    version << "Using LLVM " << LLVM_VERSION_STRING << std::endl;

    google::SetVersionString(version.str());
}

int main(int argc, char* argv[]) {
    SetVersion();
    google::SetUsageMessage("IRENE3 decompiler");
    google::ParseCommandLineNonHelpFlags(&argc, &argv, false);
    google::InitGoogleLogging(argv[0]);

    if (argc <= 1 || FLAGS_help || FLAGS_h) {
        google::ShowUsageWithFlagsRestrict(argv[0], __FILE__);
        return EXIT_FAILURE;
    }

    google::HandleCommandLineHelpFlags();

    mlir::MLIRContext mlir_context;

    mlir::DialectRegistry registry;
    registry.insert< irene3::patchir::PatchIRDialect >();
    registry.insert< mlir::LLVM::LLVMDialect >();
    registry.insert< mlir::DLTIDialect >();

    //    mlir_context.getOrLoadDialect< irene3::patchir::PatchIRDialect >();
    //  mlir_context.getOrLoadDialect< mlir::LLVM::LLVMDialect >();
    // mlir_context.getOrLoadDialect< mlir::DLTIDialect >();
    mlir_context.appendDialectRegistry(registry);

    CHECK(!FLAGS_spec.empty()) << "Must specify input binary";
    std::unordered_set< uint64_t > target_funcs;
    if (!FLAGS_lift_list.empty()) {
        std::stringstream ss(FLAGS_lift_list);

        for (uint64_t addr; ss >> std::hex >> addr;) {
            target_funcs.insert(addr);
            LOG(INFO) << "Added target " << std::hex << addr;
            if (ss.peek() == ',') {
                ss.ignore();
            }
        }
    }

    std::ifstream spec_stream(FLAGS_spec);
    irene3::PatchIRCodegen codegen(mlir_context, spec_stream, std::move(target_funcs));
    auto mlir_module = codegen.GetMLIRModule();
    CHECK(mlir_module->verify().succeeded());
    if (FLAGS_mlir_out.empty()) {
        mlir_module->print(llvm::outs());
    } else {
        std::error_code ec;
        llvm::raw_fd_ostream os(FLAGS_mlir_out, ec);
        CHECK(!ec) << "Couldn't open output file `" << FLAGS_mlir_out << '`';
        mlir_module->print(os);
    }
}
