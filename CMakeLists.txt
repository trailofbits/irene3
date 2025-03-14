#
# Copyright (c) 2019-present, Trail of Bits, Inc. All rights reserved.
#
# This source code is licensed in accordance with the terms specified in the LICENSE file found in
# the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.19)

include("cmake/options.cmake")
include("cmake/ccache.cmake")

project(
  "irene3"
  LANGUAGES C CXX
  VERSION 0.0.0
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(GNUInstallDirs)
include("cmake/system.cmake")

project("irene3")

find_package(gflags CONFIG REQUIRED)
find_package(glog CONFIG REQUIRED)
find_package(Z3 CONFIG REQUIRED)
find_package(LLVM CONFIG REQUIRED)
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})
include_directories(SYSTEM ${CLANG_INCLUDE_DIRS})
find_package(remill CONFIG REQUIRED)
find_package(Protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)
find_package(MLIR CONFIG REQUIRED)

cmake_policy(SET CMP0116 NEW)

list(APPEND CMAKE_MODULE_PATH "${MLIR_CMAKE_DIR}")
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")

include(TableGen)
include(AddLLVM)
include(AddMLIR)

option(ANVILL_ENABLE_TESTS "Enable Anvill tests" OFF)
add_subdirectory("vendor/anvill" EXCLUDE_FROM_ALL)
option(RELLIC_ENABLE_TESTING "Enable rellic tests" OFF)
add_subdirectory("vendor/rellic" EXCLUDE_FROM_ALL)

# gRPC and protobuf setup. Needs to be in this top-level CMake file due to limitations in CMake
# script when including proto files in parent directories of the CMake call to generate.
set(PROTO_BINARY_DIR "${PROJECT_BINARY_DIR}/generated")

# Third-party protobufs need to be generated carefully to get import directories to play nice across
# CMake and gradle
add_subdirectory(vendor)

# IRENE protobuf objects target
add_library(irene3_proto-objects OBJECT bin/Codegen/service.proto bin/PatchLangServer/patch_service.proto)

target_link_libraries(irene3_proto-objects PUBLIC protobuf::libprotobuf gRPC::grpc++ irene3_ext-proto-objects)
target_include_directories(irene3_proto-objects PUBLIC "$<BUILD_INTERFACE:${PROTO_BINARY_DIR}>")

set(PROTO_IMPORT_DIRS "${PROJECT_SOURCE_DIR}/vendor")

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
add_subdirectory(include)
add_subdirectory(utils)
add_subdirectory(lib)
add_subdirectory(bin)

if(IRENE3_ENABLE_INSTALL)
  install(TARGETS PatchIR)
  export(PACKAGE "${PROJECT_NAME}")
  set(CMAKE_INSTALL_DIR "lib/cmake/${PROJECT_NAME}")

  include(CMakePackageConfigHelpers)
  configure_package_config_file(
    "cmake/${PROJECT_NAME}Config.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_DIR}"
  )

  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
    DESTINATION "${CMAKE_INSTALL_DIR}"
  )
  install(
    EXPORT "${PROJECT_NAME}Targets"
    DESTINATION "${CMAKE_INSTALL_DIR}"
    NAMESPACE "${PROJECT_NAME}::"
  )
endif(IRENE3_ENABLE_INSTALL)

# tests
if(IRENE3_ENABLE_TESTS)
  include(CTest)

  find_package(Clang CONFIG REQUIRED)
  get_target_property(CLANG_PATH clang LOCATION)
  message(STATUS "Clang path for tests: \"${CLANG_PATH}\"")

  set(PYTHON_FIND_VIRTUALENV FIRST)

  if(EXISTS ${CMAKE_SOURCE_DIR}/venv)
    message(STATUS "Using virtualenv ${CMAKE_SOURCE_DIR}/venv")
    set(Python3_ROOT_DIR "${CMAKE_SOURCE_DIR}/venv")
  endif()

  find_package(
    Python3
    COMPONENTS Interpreter
    REQUIRED
  )
  message(STATUS "Python path for tests: \"${Python3_EXECUTABLE}\"")

  add_test(
    NAME test_irene3_decompile
    COMMAND "${Python3_EXECUTABLE}" scripts/decompile.py $<TARGET_FILE:${IRENE3_DECOMP}> tests/specs
    --timeout 30
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  )

  if(IRENE3_TEST_ROUNDTRIP)
    add_test(
      NAME test_irene3_roundtrip
      COMMAND "${Python3_EXECUTABLE}" scripts/roundtrip.py $<TARGET_FILE:${IRENE3_DECOMP}> tests/c
      "${CLANG_PATH}" --timeout 30
      WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )
  endif(IRENE3_TEST_ROUNDTRIP)
endif(IRENE3_ENABLE_TESTS)
