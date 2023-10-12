/*
 * Copyright (c) 2023-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "anvill/data_specifications/specification.pb.h"
#include "bin/Codegen/service.grpc.pb.h"
#include "bin/Codegen/service.pb.h"
#include "codegen_common.h"

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/sync_stream.h>
#include <iostream>
#include <llvm/Support/JSON.h>
#include <llvm/Support/raw_ostream.h>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

// Similar options as the CLI-only program
DEFINE_int32(port, 50080, "server port <65536");
// NOTE(ekilmer): This is in the CLI Main.cpp but not sure if it makes sense for a server
// DEFINE_string(lift_list, "", "list of entities to lift");
DEFINE_bool(args_as_locals, true, "arguments as locals");
DEFINE_bool(add_edges, false, "add outgoing edges to blocks for cfg construction");
DEFINE_bool(type_propagation, false, "perform type propagation");
DEFINE_bool(unsafe_stack_locations, false, "create separate locals for each stack location");
DEFINE_bool(h, false, "help");

DECLARE_bool(version);
DECLARE_bool(help);

using grpc::ServerContext;
using grpc::Status;
using irene::server::Codegen;
using irene::server::Irene;
using specification::Specification;

class IreneImpl final : public Irene::Service {
  public:
    explicit IreneImpl(
        bool propagate_types, bool args_as_locals, bool unsafe_stack_locations, bool add_edges)
        : propagate_types(propagate_types)
        , args_as_locals(args_as_locals)
        , unsafe_stack_locations(unsafe_stack_locations)
        , add_edges(add_edges) {}

    Status ProcessSpecification(
        ServerContext *context,
        ::grpc::ServerReader< ::irene::server::SpecChunk > *reader,
        Codegen *response) override {
        LOG(INFO) << "-------------- ProcessSpecification --------------";
        LOG(INFO) << "Reading specification...";
        std::unordered_set< uint64_t > target_funcs;
        irene::server::SpecChunk chunk;
        std::vector< uint8_t > bytes;
        int ctr = 0;
        while (reader->Read(&chunk)) {
            for (auto byte : chunk.chunk()) {
                bytes.push_back(byte);
            }
            LOG(INFO) << "Stored chunk " << ctr;
            ctr++;
        }
        LOG(INFO) << "Done!";

        LOG(INFO) << "Parsing spec...";
        specification::Specification spec;
        spec.ParseFromArray(bytes.data(), bytes.size());
        LOG(INFO) << "Done!";

        LOG(INFO) << "Processing spec...";
        auto maybe_result = ::ProcessSpecification(
            spec.SerializeAsString(), target_funcs, propagate_types, args_as_locals,
            unsafe_stack_locations, add_edges, this->is_vibes);
        if (!maybe_result.Succeeded()) {
            LOG(ERROR) << "Error ocurred: " << maybe_result.TakeError();
            return { grpc::StatusCode::INTERNAL, maybe_result.TakeError() };
        }
        LOG(INFO) << "Done!";

        LOG(INFO) << "Sending response...";
        std::string out;
        llvm::raw_string_ostream out_stream(out);
        out_stream << llvm::json::Value(maybe_result.TakeValue());
        response->set_json(out_stream.str());
        LOG(INFO) << "Done!";
        return Status::OK;
    }

  private:
    bool propagate_types        = false;
    bool args_as_locals         = false;
    bool unsafe_stack_locations = true;
    bool add_edges              = false;
    bool is_vibes               = true;
};

void RunServer(grpc::ServerBuilder &builder, int32_t port, IreneImpl &service) {
    std::string server_address("0.0.0.0:" + std::to_string(port));

    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    std::unique_ptr< grpc::Server > server(builder.BuildAndStart());
    std::cerr << "Server listening on " << server_address << "\n";
    server->Wait();
}

int main(int argc, char *argv[]) {
    SetVersion();
    google::SetUsageMessage("IRENE3 gRPC codegen");
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

    IreneImpl service(
        FLAGS_type_propagation, FLAGS_args_as_locals, FLAGS_unsafe_stack_locations,
        FLAGS_add_edges);

    grpc::ServerBuilder builder;
    RunServer(builder, FLAGS_port, service);

    return EXIT_SUCCESS;
}
