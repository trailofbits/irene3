#
# Copyright (c) 2022-present, Trail of Bits, Inc. All rights reserved.
#
# This source code is licensed in accordance with the terms specified in the LICENSE file found in
# the root directory of this source tree.
#

# --- gRPC codegen creation
find_package(Protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)

add_library(irene3_proto-objects OBJECT service.proto ../../data_specifications/specification.proto)
target_link_libraries(irene3_proto-objects PUBLIC protobuf::libprotobuf gRPC::grpc++)

set(PROTO_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
set(PROTO_IMPORT_DIRS "${PROJECT_SOURCE_DIR}")

target_include_directories(irene3_proto-objects PUBLIC "$<BUILD_INTERFACE:${PROTO_BINARY_DIR}>")

# cmake-format: off
protobuf_generate(
    OUT_VAR PROTO_GENERATED_FILES
    TARGET irene3_proto-objects
    IMPORT_DIRS ${PROTO_IMPORT_DIRS}
    PROTOC_OUT_DIR "${PROTO_BINARY_DIR}"
)
set_source_files_properties(${PROTO_GENERATED_FILES} PROPERTIES SKIP_UNITY_BUILD_INCLUSION ON)

protobuf_generate(
    OUT_VAR PROTO_GENERATED_FILES
    TARGET irene3_proto-objects
    LANGUAGE grpc
    GENERATE_EXTENSIONS .grpc.pb.h .grpc.pb.cc
    PLUGIN "protoc-gen-grpc=\$<TARGET_FILE:gRPC::grpc_cpp_plugin>"
    IMPORT_DIRS ${PROTO_IMPORT_DIRS}
    PROTOC_OUT_DIR "${PROTO_BINARY_DIR}"
)
set_source_files_properties(${PROTO_GENERATED_FILES} PROPERTIES SKIP_UNITY_BUILD_INCLUSION ON)
# cmake-format: on

# --- gRPC server
add_executable(irene3_server Server.cpp codegen_common.cpp)
add_executable(irene3::server ALIAS irene3_server)

set_property(TARGET irene3_server PROPERTY OUTPUT_NAME irene3-server)

target_compile_features(irene3_server PRIVATE cxx_std_17)
target_link_libraries(irene3_server PRIVATE irene3 irene3_proto-objects glog::glog gflags::gflags)

# --- gRPC client
add_executable(irene3_client Client.cpp)
add_executable(irene3::client ALIAS irene3_client)

set_property(TARGET irene3_client PROPERTY OUTPUT_NAME irene3-client)

target_compile_features(irene3_client PRIVATE cxx_std_17)
target_link_libraries(irene3_client PRIVATE irene3 irene3_proto-objects glog::glog gflags::gflags)

# --- CLI codegen tool
string(TOLOWER "${PROJECT_NAME}" lower_project_name)
set(IRENE3_CODEGEN "${lower_project_name}-codegen")
set(IRENE3_CODEGEN
    "${IRENE3_CODEGEN}"
    PARENT_SCOPE
)

add_executable("${IRENE3_CODEGEN}" Main.cpp codegen_common.cpp)

set_target_properties("${IRENE3_CODEGEN}" PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries("${IRENE3_CODEGEN}" PRIVATE irene3)
target_include_directories(
  "${IRENE3_CODEGEN}" PRIVATE "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
)

if (IRENE3_ENABLE_INSTALL)
  install(
    TARGETS irene3_server irene3_client "${IRENE3_CODEGEN}"
    EXPORT irene3Targets
    RUNTIME DESTINATION bin
  )
endif (IRENE3_ENABLE_INSTALL)
