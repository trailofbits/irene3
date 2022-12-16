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
find_package(remill CONFIG REQUIRED)


set(ANVILL_ENABLE_TESTS OFF)
add_subdirectory("vendor/anvill" EXCLUDE_FROM_ALL)
set(RELLIC_ENABLE_TESTING OFF)
add_subdirectory("vendor/rellic" EXCLUDE_FROM_ALL)

set(PASTA_ENABLE_TESTING OFF)
add_subdirectory("vendor/pasta" EXCLUDE_FROM_ALL)

if(IRENE3_ENABLE_INSTALL)
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

add_subdirectory(lib)
add_subdirectory(bin)

# tests
if(IRENE3_ENABLE_TESTS)
  include(CTest)

  find_package(Clang CONFIG REQUIRED)
  get_target_property(CLANG_PATH clang LOCATION)
  message(STATUS "Clang path for tests: \"${CLANG_PATH}\"")

  set(PYTHON_FIND_VIRTUALENV FIRST)
  if (EXISTS ${CMAKE_SOURCE_DIR}/venv)
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
      COMMAND "${Python3_EXECUTABLE}" scripts/roundtrip.py $<TARGET_FILE:${IRENE3_DECOMP}> tests/c "${CLANG_PATH}"
      --timeout 30
      WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )
  endif(IRENE3_TEST_ROUNDTRIP)
endif(IRENE3_ENABLE_TESTS)
