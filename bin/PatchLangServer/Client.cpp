#include "bin/PatchLangServer/patch_service.grpc.pb.h"
#include "bin/PatchLangServer/patch_service.pb.h"

#include <anvill/data_specifications/specification.pb.h>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <google/protobuf/util/json_util.h>
#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/credentials.h>
#include <grpcpp/support/sync_stream.h>
#include <iostream>
#include <iterator>

DEFINE_string(api, "", "the server api to call [generate, patch]");
DEFINE_string(spec_in, "", "input spec to send when calling generate");
DEFINE_string(patch_out, "", "output patchlang graph when calling generate");
DEFINE_string(
    patch_blocks_out_dir,
    "",
    "output directory to write patchlang blocks to make patching easy; empty means that the blocks "
    "won't be written");
DEFINE_string(patch_in, "", "input patchlang source when calling patch");
DEFINE_int32(patch_uid, -1, "input patchlang block uid to patch");
DEFINE_int32(port, 50080, "server port <65536");
DEFINE_bool(h, false, "help");

DECLARE_bool(version);
DECLARE_bool(help);

class PatchLangClient {
  public:
    explicit PatchLangClient(const std::shared_ptr< grpc::Channel >& channel)
        : stub_(irene3::server::PatchLangServer::NewStub(channel)) {}

    bool GeneratePatchGraph(
        const specification::Specification& spec, irene3::server::PatchGraph& resp) {
        grpc::ClientContext context;
        std::unique_ptr< grpc::ClientWriter< irene3::server::SpecChunk > > writer(
            stub_->GeneratePatchGraph(&context, &resp));
        auto out_str = spec.SerializeAsString();

        LOG(INFO) << "Sending...";
        size_t ind = 0;
        while (ind < out_str.length()) {
            irene3::server::SpecChunk chunk;
            std::string cbytes = out_str.substr(ind, ind + CHUNK_SIZE);
            chunk.set_chunk(cbytes);
            if (!writer->Write(chunk)) {
                LOG(ERROR) << "Broken stream while writing spec\n";
                // Broken stream
                return false;
            }
            LOG(INFO) << "Sent chunk index " << ind << "\n";
            ind += CHUNK_SIZE;
        }

        writer->WritesDone();
        auto status = writer->Finish();
        if (!status.ok()) {
            LOG(ERROR) << "GeneratePatchGraph rpc failed with message:\n\""
                       << status.error_message() << "\"\nand details:\n\"" << status.error_details()
                       << "\"";
            return false;
        }
        LOG(INFO) << "Sent specification!\n";
        return true;
    }

    bool ApplyPatch(
        const irene3::server::PatchRequest& preq, irene3::server::PatchResponse& presp) {
        grpc::ClientContext context;
        const auto status = stub_->ApplyPatch(&context, preq, &presp);
        if (!status.ok()) {
            LOG(ERROR) << "ApplyPatch rpc failed with message:\n\"" << status.error_message()
                       << "\"\nand details:\n\"" << status.error_details() << "\"";
            return false;
        }
        LOG(INFO) << "Sent patch!";
        return true;
    }

  private:
    static const size_t CHUNK_SIZE = 2000000;
    std::unique_ptr< irene3::server::PatchLangServer::Stub > stub_;
};

int main(int argc, char** argv) {
    google::SetUsageMessage("IRENE3 gRPC PatchLang Client");
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

    if (FLAGS_api.empty()) {
        google::ShowUsageWithFlagsRestrict(argv[0], __FILE__);
        std::cerr << "API must be specified via the -api flag\n";
        return EXIT_FAILURE;
    }

    google::HandleCommandLineHelpFlags();

    // Send spec to server
    PatchLangClient client(grpc::CreateChannel(
        "localhost:" + std::to_string(FLAGS_port), grpc::InsecureChannelCredentials()));

    // TODO(alex): Doesn't seem like GFlags supports subcommands like you can do with Python's
    // argparse. Not sure if there's a better way of doing this.
    if (FLAGS_api == "generate") {
        if (FLAGS_spec_in.empty()) {
            google::ShowUsageWithFlagsRestrict(argv[0], __FILE__);
            std::cerr << "Spec input must be specified when using generate api\n";
            return EXIT_FAILURE;
        }
        if (FLAGS_patch_out.empty()) {
            google::ShowUsageWithFlagsRestrict(argv[0], __FILE__);
            std::cerr << "Patch graph output must be specified when using generate api\n";
            return EXIT_FAILURE;
        }
        std::ifstream is(FLAGS_spec_in);
        if (!is.is_open()) {
            google::ShowUsageWithFlagsRestrict(argv[0], __FILE__);
            std::cerr << "Spec input \"" << FLAGS_spec_in << "\" doesn't exist\n";
            return EXIT_FAILURE;
        }
        std::string buffer(
            (std::istreambuf_iterator< char >(is)), std::istreambuf_iterator< char >());
        specification::Specification spec;
        if (!spec.ParseFromString(buffer)) {
            auto status = google::protobuf::util::JsonStringToMessage(buffer, &spec);
            if (!status.ok()) {
                LOG(FATAL) << "Failed to parse specification: " << status.ToString();
            }
        }
        LOG(INFO) << "Sending spec with " << spec.functions().size() << " functions";

        LOG(INFO) << "-------------- GeneratePatchGraph --------------" << std::endl;
        irene3::server::PatchGraph pgraph;
        if (!client.GeneratePatchGraph(spec, pgraph)) {
            LOG(FATAL) << "GeneratePatchGraph rpc failed!";
        }

        // Write patch graph JSON to file
        std::string pgraph_str;
        google::protobuf::util::MessageToJsonString(pgraph, &pgraph_str);
        std::ofstream pgraph_stream(FLAGS_patch_out);
        pgraph_stream << pgraph_str;

        // Write a patchlang source file for each block for convenient patching
        if (!FLAGS_patch_blocks_out_dir.empty()) {
            std::filesystem::path pblks_path(FLAGS_patch_blocks_out_dir);
            if (!std::filesystem::exists(pblks_path)
                && !std::filesystem::create_directory(pblks_path)) {
                LOG(FATAL) << "Failed to create directory: " << pblks_path;
            }
            for (const auto& pblk : pgraph.blocks()) {
                auto pblk_path
                    = pblks_path / ("region_" + std::to_string(pblk.first) + ".patchlang");
                std::ofstream pblk_stream(pblk_path);
                pblk_stream << pblk.second.code();
            }
        }

        LOG(INFO) << "Done!";
    } else if (FLAGS_api == "patch") {
        if (FLAGS_patch_in.empty()) {
            google::ShowUsageWithFlagsRestrict(argv[0], __FILE__);
            std::cerr << "Patch input must be specified when using patch api\n";
            return EXIT_FAILURE;
        }
        if (FLAGS_patch_uid < 0) {
            google::ShowUsageWithFlagsRestrict(argv[0], __FILE__);
            std::cerr << "Patch uid must be specified when using patch api\n";
            return EXIT_FAILURE;
        }

        // Put together patch request
        std::ifstream pgraph_new_code_stream(FLAGS_patch_in);
        if (!pgraph_new_code_stream.is_open()) {
            google::ShowUsageWithFlagsRestrict(argv[0], __FILE__);
            std::cerr << "Patch input \"" << FLAGS_patch_in << "\" doesn't exist\n";
            return EXIT_FAILURE;
        }
        std::string pgraph_new_code(
            (std::istreambuf_iterator< char >(pgraph_new_code_stream)),
            std::istreambuf_iterator< char >());
        irene3::server::PatchRequest preq;
        preq.set_uid(FLAGS_patch_uid);
        preq.set_new_code(pgraph_new_code);

        // Call apply patch API
        irene3::server::PatchResponse presp;
        if (!client.ApplyPatch(preq, presp)) {
            LOG(FATAL) << "ApplyPatch rpc failed!";
        }

        // Print the new code
        LOG(INFO) << presp.new_code();
        LOG(INFO) << "Done!";
    } else {
        google::ShowUsageWithFlagsRestrict(argv[0], __FILE__);
        std::cerr << "API must be one of [generate, patch]\n";
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
