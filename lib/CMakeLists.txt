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

set(include_dir "${PROJECT_SOURCE_DIR}/include")

set(VERSION_HEADERS "${include_dir}/${PROJECT_NAME}/Version.h")

set(irene3_PUBLIC_HEADER_DIR "${PROJECT_SOURCE_DIR}/include/irene3")

set(irene3_PUBLIC_HEADERS "${irene3_PUBLIC_HEADER_DIR}/Version.h" "${irene3_PUBLIC_HEADER_DIR}/DecompileSpec.h")

set(irene3_SOURCES "${POST_CONFIGURE_FILE}" DecompileSpec.cpp Util.cpp SpecTypeProvider.cpp)

add_library("${PROJECT_NAME}" STATIC ${irene3_PUBLIC_HEADERS} ${irene3_SOURCES})

set_target_properties(
  "${PROJECT_NAME}" PROPERTIES PUBLIC_HEADER "${irene3_PUBLIC_HEADERS}" LINKER_LANGUAGE CXX
)

# link version information
target_link_libraries("${PROJECT_NAME}" PUBLIC glog::glog "${llvm_libs}" gflags rellic anvill pasta)

target_include_directories(
  "${PROJECT_NAME}"
  PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>
  PRIVATE "${CMAKE_CURRENT_LIST_DIR}"
)

add_dependencies(irene3 check_git_irene3)

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
