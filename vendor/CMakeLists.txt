# This protobuf compilation and target needs to be done here due to weird protoc
# compilation issues with disallowing parent directories.
#
# IRENE 3rd party protobuf objects target.
add_library(
    irene3_ext-proto-objects OBJECT
      anvill/data_specifications/specification.proto
)

target_link_libraries(irene3_ext-proto-objects PUBLIC protobuf::libprotobuf gRPC::grpc++)
target_include_directories(irene3_ext-proto-objects PUBLIC "$<BUILD_INTERFACE:${PROTO_BINARY_DIR}>")

# cmake-format: off
protobuf_generate(
    OUT_VAR PROTO_GENERATED_FILES
    TARGET irene3_ext-proto-objects
    PROTOC_OUT_DIR "${PROTO_BINARY_DIR}"
)
set_source_files_properties(${PROTO_GENERATED_FILES} PROPERTIES SKIP_UNITY_BUILD_INCLUSION ON)

protobuf_generate(
    OUT_VAR PROTO_GENERATED_FILES
    TARGET irene3_ext-proto-objects
    LANGUAGE grpc
    GENERATE_EXTENSIONS .grpc.pb.h .grpc.pb.cc
    PLUGIN "protoc-gen-grpc=\$<TARGET_FILE:gRPC::grpc_cpp_plugin>"
    PROTOC_OUT_DIR "${PROTO_BINARY_DIR}"
)
set_source_files_properties(${PROTO_GENERATED_FILES} PROPERTIES SKIP_UNITY_BUILD_INCLUSION ON)
# cmake-format: on
