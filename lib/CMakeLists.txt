#
# Copyright (c) 2020-present, Trail of Bits, Inc. All rights reserved.
#
# This source code is licensed in accordance with the terms specified in the LICENSE file found in
# the root directory of this source tree.
#

# Based on:
# https://github.com/andrew-hardin/cmake-git-version-tracking/blob/master/better-example/CMakeLists.txt
# By Andrew Hardin Released under the MIT License.
# https://raw.githubusercontent.com/andrew-hardin/cmake-git-version-tracking/master/LICENSE
#
# Define the two required variables before including the source code for watching a git repository.
set(PRE_CONFIGURE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/Version.cpp.in")
set(POST_CONFIGURE_FILE "${CMAKE_CURRENT_BINARY_DIR}/Version.cpp")
set(GIT_WORKING_DIR "${PROJECT_SOURCE_DIR}")
include("${PROJECT_SOURCE_DIR}/cmake/git_watcher.cmake")

add_subdirectory(PatchIR)

set(include_dir "${PROJECT_SOURCE_DIR}/include")

set(VERSION_HEADERS "${include_dir}/${PROJECT_NAME}/Version.h")

set(irene3_PUBLIC_HEADER_DIR "${PROJECT_SOURCE_DIR}/include/irene3")

set(irene3_PUBLIC_HEADERS "${irene3_PUBLIC_HEADER_DIR}/Version.h" "${irene3_PUBLIC_HEADER_DIR}/DecompileSpec.h")

find_program(RE2C "re2c" REQUIRED)
find_package(gap CONFIG REQUIRED)

set(irene3_SOURCES
  "${POST_CONFIGURE_FILE}"
  DecompileSpec.cpp
  IreneLoweringInterface.cpp
  Util.cpp
  SpecTypeProvider.cpp
  SpecLayoutOverride.cpp
  TypeDecoder.cpp
  UnsafeSpecLayoutOverride.cpp
  PatchCompiler.cpp
  PhysicalLocationDecoder.cpp
  LowLocCCBuilder.cpp
  Transforms/RemoveProgramCounterAndMemory.cpp
  Transforms/WrapFunctionWithMachineWrapper.cpp
  Transforms/ReplaceRelReferences.cpp
  PatchLang/Expr.cpp
  PatchLang/Parser.cpp
  PatchLang/Lifter.cpp
  "${CMAKE_CURRENT_BINARY_DIR}/Lexer.cpp"

  Targets/Backends.cpp
  PatchLang/Stmt.cpp
  PatchLang/Type.cpp
  Targets/GenericBackend.cpp
  Targets/ExplicitMappingBackend.cpp
)

add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/Backend.inc"
  COMMAND "irene3-generate-target" ARGS "${CMAKE_CURRENT_SOURCE_DIR}/Targets/Backend.td" -o "${CMAKE_CURRENT_BINARY_DIR}/Backend.inc" -I "${CMAKE_CURRENT_SOURCE_DIR}/Targets" -I "${LLVM_INCLUDE_DIRS}"
  DEPENDS "irene3-generate-target" "${CMAKE_CURRENT_SOURCE_DIR}/Targets/Backend.td" "${CMAKE_CURRENT_SOURCE_DIR}/Targets/PPCBackend.td")
add_custom_target(backend_tblgen DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/Backend.inc")
add_custom_command(
  OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/Lexer.cpp"
  COMMAND "${RE2C}"
  ARGS
  "${CMAKE_CURRENT_SOURCE_DIR}/PatchLang/Lexer.cpp.re"
  -o "${CMAKE_CURRENT_BINARY_DIR}/Lexer.cpp"
  --depfile "${CMAKE_CURRENT_BINARY_DIR}/Lexer.cpp.d"
  DEPFILE "${CMAKE_CURRENT_BINARY_DIR}/Lexer.cpp.d"
  COMMENT "Generating lexer")

add_library("${PROJECT_NAME}" STATIC ${irene3_PUBLIC_HEADERS} ${irene3_SOURCES})

set_target_properties(
  "${PROJECT_NAME}" PROPERTIES PUBLIC_HEADER "${irene3_PUBLIC_HEADERS}" LINKER_LANGUAGE CXX
)

llvm_map_components_to_libnames(llvm_libs AllTargetsCodeGens)

# link version information
target_link_libraries("${PROJECT_NAME}" PUBLIC gap::gap glog::glog "${llvm_libs}" gflags rellic anvill PatchIR)

target_include_directories(
  "${PROJECT_NAME}"
  PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>
  PRIVATE "${CMAKE_CURRENT_LIST_DIR}" "${CMAKE_CURRENT_BINARY_DIR}"
)

add_dependencies(irene3 check_git_irene3 backend_tblgen)

if(IRENE3_ENABLE_INSTALL)
  include(GNUInstallDirs)

  # install(DIRECTORY "${include_dir}" DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
  install(
    TARGETS "${PROJECT_NAME}"
    EXPORT "${PROJECT_NAME}Targets"
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}"
  )
endif(IRENE3_ENABLE_INSTALL)
