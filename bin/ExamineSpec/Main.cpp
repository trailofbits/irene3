

#include "anvill/Declarations.h"

#include <anvill/Specification.h>
#include <fstream>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <iostream>
#include <llvm/IR/LLVMContext.h>
#include <memory>

DEFINE_string(spec, "", "Target spec");
DEFINE_bool(h, false, "help");
DECLARE_bool(help);

int main(int argc, char* argv[]) {
    google::SetUsageMessage("IRENE3 MLIR Lifter");
    google::ParseCommandLineNonHelpFlags(&argc, &argv, false);
    google::InitGoogleLogging(argv[0]);

    if (argc <= 1 || FLAGS_help || FLAGS_h) {
        google::ShowUsageWithFlagsRestrict(argv[0], __FILE__);
        return EXIT_FAILURE;
    }

    std::ifstream spec_stream(FLAGS_spec);

    llvm::LLVMContext llvm_context;
    auto spec = anvill::Specification::DecodeFromPB(llvm_context, spec_stream);
    if (spec.Succeeded()) {
        spec->ForEachFunction([](const std::shared_ptr< const anvill::FunctionDecl > func) {
            std::cout << "Func: " << std::hex << func->address << std::endl;

            size_t indent = 4;
            for (auto [uid, blk] : func->cfg) {
                std::cout << std::string(indent, ' ') << "Block uid: " << std::dec << uid.value
                          << " address: " << std::hex << blk.addr << std::endl;

                for (auto out_edge : blk.outgoing_edges) {
                    std::cout << std::string(indent + 4, ' ') << std::dec << out_edge.value
                              << std::endl;
                }
            }

            return true;
        });
    }
}