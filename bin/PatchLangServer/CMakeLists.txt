#
# Copyright (c) 2024-present, Trail of Bits, Inc. All rights reserved.
#
# This source code is licensed in accordance with the terms specified in the LICENSE file found in
# the root directory of this source tree.
#

# --- gRPC server
add_executable(irene3_patchlang_server Server.cpp)
add_executable(irene3::patchlang_server ALIAS irene3_patchlang_server)

set_property(TARGET irene3_patchlang_server PROPERTY OUTPUT_NAME irene3-patchlang-server)

target_compile_features(irene3_patchlang_server PRIVATE cxx_std_17)
target_link_libraries(irene3_patchlang_server PRIVATE
  irene3
  irene3_proto-objects
  irene3_ext-proto-objects
  glog::glog
  gflags::gflags
  PatchIR
  MLIRLLVMDialect
  MLIRLLVMIRToLLVMTranslation
  )

# --- gRPC client
add_executable(irene3_patchlang_client Client.cpp)
add_executable(irene3::patchlang_client ALIAS irene3_patchlang_client)

set_property(TARGET irene3_patchlang_client PROPERTY OUTPUT_NAME irene3-patchlang-client)

target_compile_features(irene3_patchlang_client PRIVATE cxx_std_17)
target_link_libraries(irene3_patchlang_client PRIVATE
  irene3
  irene3_proto-objects
  irene3_ext-proto-objects
  glog::glog
  gflags::gflags
  PatchIR
  MLIRLLVMDialect
  MLIRLLVMIRToLLVMTranslation
  )

if (IRENE3_ENABLE_INSTALL)
  install(
    TARGETS irene3_patchlang_server irene3_patchlang_client
    EXPORT irene3Targets
    RUNTIME DESTINATION bin
  )
endif (IRENE3_ENABLE_INSTALL)
