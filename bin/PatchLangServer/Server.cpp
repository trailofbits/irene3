#include "bin/PatchLangServer/patch_service.grpc.pb.h"
#include "bin/PatchLangServer/patch_service.pb.h"

#include <anvill/Declarations.h>
#include <anvill/Specification.h>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <grpcpp/server_builder.h>
#include <irene3/PatchIR/PatchIRDialect.h>
#include <irene3/PatchIRCodegen.h>
#include <irene3/PatchLang/Lifter.h>
#include <irene3/PatchLang/Parser.h>
#include <irene3/PatchLang/SExprPrinter.h>
#include <irene3/PatchLang/Stmt.h>
#include <mlir/Dialect/DLTI/DLTIDialect.h.inc>
#include <mlir/IR/MLIRContext.h>
#include <sstream>
#include <variant>

DEFINE_int32(port, 50080, "server port <65536");
DEFINE_bool(h, false, "help");

DECLARE_bool(version);
DECLARE_bool(help);

void PrintRegionBody(std::ostream &os, const irene3::patchlang::Region &reg) {
    // We don't want clients seeing a trailing newline so add a check for that.
    for (const auto &stmt : reg.GetBody()) {
        if (&stmt != &reg.GetBody().front()) {
            os << '\n';
        }
        irene3::patchlang::PrintSExpr(os, stmt);
    }
}

irene3::server::PatchGraph BuildPatchGraph(
    irene3::patchlang::PModule &pmod, const anvill::Specification &spec) {
    irene3::server::PatchGraph pgraph;
    auto *blks = pgraph.mutable_blocks();
    for (const auto &decl : pmod.GetDecls()) {
        if (std::holds_alternative< irene3::patchlang::Function >(decl)) {
            const auto &func = std::get< irene3::patchlang::Function >(decl);
            for (const auto &reg : func.GetRegions()) {
                // For each region, we want to build one block in the patch graph.
                auto reg_uid  = reg.GetUID().GetValue().getZExtValue();
                auto reg_addr = reg.GetAddress().GetValue().getZExtValue();
                LOG(INFO) << "Building patch graph block for region: " << reg_uid;

                irene3::server::PatchBlock new_blk;
                new_blk.set_uid(reg_uid);
                new_blk.set_address(reg_addr);
                new_blk.set_size(static_cast< uint64_t >(reg.GetSize()));

                // Find matching block in spec.
                // This will tell us what edges the region has.
                auto spec_blk_ptr = spec.BlockAt(anvill::Uid{ reg_uid });
                CHECK(spec_blk_ptr);
                auto spec_blk = *spec_blk_ptr;
                for (const auto outgoing : spec_blk.outgoing_edges) {
                    new_blk.add_edges(outgoing.value);
                }

                // Only print the statements within the region since we don't want clients to
                // try to patch data about the region such as the UID, address, etc.
                std::stringstream ss;
                PrintRegionBody(ss, reg);
                new_blk.set_code(ss.str());

                blks->emplace(reg_uid, std::move(new_blk));
            }
        }
    }
    return pgraph;
}

class PatchLangServerImpl final : public irene3::server::PatchLangServer::Service {
  private:
    mlir::MLIRContext mlir_context;
    mlir::OwningOpRef< mlir::ModuleOp > mlir_module;

  public:
    grpc::Status GeneratePatchGraph(
        grpc::ServerContext *context,
        grpc::ServerReader< irene3::server::SpecChunk > *reader,
        irene3::server::PatchGraph *response) override {
        LOG(INFO) << "-------------- GeneratePatchGraph --------------";
        LOG(INFO) << "Reading specification...";
        std::unordered_set< uint64_t > target_funcs;
        irene3::server::SpecChunk chunk;
        std::vector< uint8_t > bytes;
        int ctr = 0;
        while (reader->Read(&chunk)) {
            for (auto byte : chunk.chunk()) {
                bytes.push_back(byte);
            }
            LOG(INFO) << "Stored chunk " << ctr;
            ctr++;
        }
        std::istringstream spec_stream(
            std::string(reinterpret_cast< char * >(bytes.data()), bytes.size()));
        LOG(INFO) << "Done!";

        LOG(INFO) << "Generating PatchIR...";
        mlir::DialectRegistry registry;
        registry.insert< irene3::patchir::PatchIRDialect >();
        registry.insert< mlir::LLVM::LLVMDialect >();
        registry.insert< mlir::DLTIDialect >();
        mlir_context.appendDialectRegistry(registry);
        std::optional< irene3::PatchIRCodegen > codegen;
        try {
            codegen.emplace(mlir_context, spec_stream);
        } catch (const std::runtime_error &err) {
            LOG(ERROR) << "Error generating PatchIR for spec: " << err.what();
            return grpc::Status::CANCELLED;
        }
        mlir_module = codegen->GetMLIRModule();
        CHECK(mlir_module->verify().succeeded());
        LOG(INFO) << "Done!";

        LOG(INFO) << "Generating PatchLang...";
        const auto &spec = codegen->GetSpecification();
        std::optional< irene3::patchlang::PModule > pmod;
        try {
            pmod = irene3::patchlang::LiftPatchLangModule(mlir_context, *mlir_module);
        } catch (const irene3::patchlang::UnhandledMLIRLift &err) {
            LOG(ERROR) << "Error lifting PatchLang module: " << err.what();
            return grpc::Status::CANCELLED;
        }
        irene3::patchlang::PrintSExpr(std::cout, *pmod);
        LOG(INFO) << "Done!";

        LOG(INFO) << "Sending response...";
        *response = BuildPatchGraph(*pmod, spec);
        LOG(INFO) << "Done!";
        return grpc::Status::OK;
    }

    grpc::Status ApplyPatch(
        grpc::ServerContext *context,
        const irene3::server::PatchRequest *request,
        irene3::server::PatchResponse *response) override {
        LOG(INFO) << "-------------- ApplyPatch --------------";
        // Ensure that we've generated the patch graph already.
        if (!mlir_module) {
            LOG(ERROR) << "Patch graph has not been generated yet";
            return grpc::Status::CANCELLED;
        }

        const auto &patch_req = *request;
        irene3::server::PatchResponse patch_resp;

        const auto target_uid  = patch_req.uid();
        const auto &new_source = patch_req.new_code();
        irene3::patchlang::Parser parser(irene3::patchlang::Lex(new_source));
        auto maybe_reg_body = parser.ParseRegionBody();
        if (!maybe_reg_body.Succeeded()) {
            LOG(ERROR) << "Syntax error: " << maybe_reg_body.TakeError();
            return grpc::Status::CANCELLED;
        }
        auto new_reg_body = maybe_reg_body.TakeValue();

        irene3::patchlang::LifterContext lifter(mlir_context, *mlir_module);
        std::optional< irene3::patchlang::PModule > pmod;
        try {
            pmod = irene3::patchlang::LiftPatchLangModule(mlir_context, *mlir_module, target_uid);
        } catch (const irene3::patchlang::UnhandledMLIRLift &err) {
            LOG(ERROR) << "Error lifting PatchLang: " << err.what();
        }
        irene3::patchlang::Region *target_reg = nullptr;
        for (auto &decl : pmod->GetMutableDecls()) {
            if (std::holds_alternative< irene3::patchlang::Function >(decl)) {
                auto &func = std::get< irene3::patchlang::Function >(decl);
                for (auto &r : func.GetMutableRegions()) {
                    if (static_cast< uint64_t >(r.GetUID()) == target_uid) {
                        target_reg = &r;
                    }
                }
            }
        }

        if (!target_reg) {
            LOG(FATAL) << "Couldn't find region to patch with UID: " << target_uid;
        }

        CHECK(!new_reg_body.empty());
        target_reg->GetMutableBody() = std::move(new_reg_body);

        std::stringstream ss;
        PrintRegionBody(ss, *target_reg);
        patch_resp.set_uid(target_uid);
        patch_resp.set_new_code(ss.str());

        std::stringstream mod_strm;
        irene3::patchlang::PrintSExpr(mod_strm, *pmod);
        patch_resp.set_patched_module(mod_strm.str());

        LOG(INFO) << patch_resp.new_code();
        *response = patch_resp;
        LOG(INFO) << "Done!";
        return grpc::Status::OK;
    }
};

void RunServer(grpc::ServerBuilder &builder, int32_t port, PatchLangServerImpl &service) {
    std::string server_address("localhost:" + std::to_string(port));

    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    std::unique_ptr< grpc::Server > server(builder.BuildAndStart());
    LOG(INFO) << "Server listening on " << server_address;
    server->Wait();
}

int main(int argc, char *argv[]) {
    google::SetUsageMessage("IRENE3 gRPC PatchLang Server");
    google::ParseCommandLineNonHelpFlags(&argc, &argv, false);
    google::InitGoogleLogging(argv[0]);

    if (FLAGS_help || FLAGS_h) {
        google::ShowUsageWithFlagsRestrict(argv[0], __FILE__);
        return EXIT_FAILURE;
    }

    if (FLAGS_port < 0 || FLAGS_port > 65536) {
        google::ShowUsageWithFlagsRestrict(argv[0], __FILE__);
        std::cerr << "Server port must be between 0 and 65536.\n";
        return EXIT_FAILURE;
    }

    google::HandleCommandLineHelpFlags();

    PatchLangServerImpl service;

    grpc::ServerBuilder builder;
    RunServer(builder, FLAGS_port, service);

    return EXIT_SUCCESS;
}
