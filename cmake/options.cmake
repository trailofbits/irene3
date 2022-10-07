#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

include(CMakeDependentOption)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set(default_build_type "Release")
else()
  set(default_build_type "RelWithDebInfo")
endif()

set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE STRING "Build type")

option(IRENE3_ENABLE_INSTALL "Set to ON to enable the install directives. This installs the native components" TRUE)
option(IRENE3_ENABLE_TESTS "Set to ON to enable the tests" TRUE)
option(IRENE3_TEST_ROUNDTRIP "Set to ON to enable the roundtrip tests" FALSE)
option(IRENE3_ENABLE_SANITIZERS "Set to ON to enable sanitizers. May not work with VCPKG")

set(VCPKG_ROOT "" CACHE FILEPATH "Root directory to use for vcpkg-managed dependencies")

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX "/usr" CACHE PATH "Install prefix (forced)" FORCE)
endif()
