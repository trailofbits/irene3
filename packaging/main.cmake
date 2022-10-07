#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
  set(CPACK_GENERATOR "TGZ;DEB;RPM")

elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
  set(CPACK_GENERATOR "TGZ")
endif()

set(CPACK_THREADS 0)

if(IRENE3_DATA_PATH STREQUAL "")
  message(FATAL_ERROR "The IRENE3_DATA_PATH variable was not set")
endif()

if(IRENE3_PACKAGE_VERSION STREQUAL "")
  message(FATAL_ERROR "The IRENE3_PACKAGE_VERSION variable was not set")
endif()

set(CPACK_PROJECT_CONFIG_FILE "${CMAKE_CURRENT_LIST_DIR}/cmake/dispatcher.cmake")

set(CPACK_PACKAGE_DESCRIPTION "IRENE3")
set(CPACK_PACKAGE_NAME "IRENE3")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_PACKAGE_VENDOR "Trail of Bits")
set(CPACK_PACKAGE_CONTACT "peter@trailofbits.com")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://www.trailofbits.com")

