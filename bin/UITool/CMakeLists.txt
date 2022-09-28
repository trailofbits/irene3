#
# Copyright (c) 2022-present, Trail of Bits, Inc. All rights reserved.
#
# This source code is licensed in accordance with the terms specified in the LICENSE file found in
# the root directory of this source tree.
#

string(TOLOWER "${PROJECT_NAME}" lower_project_name)
set(IRENE3_UITOOL "${lower_project_name}-uitool")
set(IRENE3_UITOOL
    "${IRENE3_UITOOL}"
    PARENT_SCOPE
)

add_executable("${IRENE3_UITOOL}" "Main.cpp" "JsonDecompBuilder.cpp")

set_target_properties("${IRENE3_UITOOL}" PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries("${IRENE3_UITOOL}" PRIVATE irene3)

target_include_directories("${IRENE3_UITOOL}" PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")

if(IRENE3_ENABLE_INSTALL)
    install(
        TARGETS "${IRENE3_UITOOL}"
        EXPORT irene3Targets
        RUNTIME DESTINATION bin
    )
endif(IRENE3_ENABLE_INSTALL)