/*
 * Copyright (c) 2023-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "bin/Codegen/service.grpc.pb.h"
#include "bin/Codegen/service.pb.h"
#include "data_specifications/specification.pb.h"

#include <fstream>
#include <filesystem>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <grpc/grpc.h>
#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/credentials.h>
#include <iostream>
#include <string>

using grpc::Channel;
using grpc::ClientContext;
using grpc::ClientReader;
using grpc::ClientReaderWriter;
using grpc::ClientWriter;
using grpc::Status;

using irene::server::Codegen;
using irene::server::Irene;
using specification::Specification;

DEFINE_string(spec, "", "input spec to send");
DEFINE_bool(h, false, "help");

DECLARE_bool(help);

class IreneClient {
  public:
    explicit IreneClient(const std::shared_ptr< Channel >& channel)
        : stub_(Irene::NewStub(channel)) {}

    bool ProcessSpecification(const Specification& specification, Codegen* codegen) {
        ClientContext context;
        Status status = stub_->ProcessSpecification(&context, specification, codegen);
        if (!status.ok()) {
            std::cout << "ProcessSpecification rpc failed with message:\n\"" << status.error_message()
                      << "\"\nand details:\n\"" << status.error_details() << "\"\n";
            return false;
        }
        return true;
    }

  private:
    std::unique_ptr< Irene::Stub > stub_;
};

int main(int argc, char** argv) {
    google::SetUsageMessage("IRENE3 grpc spec client");
    google::ParseCommandLineNonHelpFlags(&argc, &argv, false);
    google::InitGoogleLogging(argv[0]);

    if (argc <= 1 || FLAGS_help || FLAGS_h) {
        google::ShowUsageWithFlagsRestrict(argv[0], __FILE__);
        return EXIT_FAILURE;
    }

    std::filesystem::path input_spec(FLAGS_spec);
    std::ifstream is(input_spec, std::ifstream::binary);
    Specification spec;
    if (is) {
        spec.ParseFromIstream(&is);
        std::cout << "Sending spec with " << spec.functions().size() << " functions.\n";
    } else {
        std::cout << "Something wrong with reading Specification protobuf file: " << input_spec
                  << "\n";
        return 1;
    }

    // Send spec to server
    IreneClient irene(grpc::CreateChannel("localhost:50080", grpc::InsecureChannelCredentials()));

    std::cout << "-------------- ProcessSpec --------------" << std::endl;
    Codegen codegen;
    irene.ProcessSpecification(spec, &codegen);
    std::cout << codegen.json();

    return 0;
}