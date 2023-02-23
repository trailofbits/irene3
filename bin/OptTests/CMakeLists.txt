#
# Copyright (c) 2022-present, Trail of Bits, Inc. All rights reserved.
#
# This source code is licensed in accordance with the terms specified in the LICENSE file found in
# the root directory of this source tree.
#

string(TOLOWER "${PROJECT_NAME}" lower_project_name)
set(IRENE3_CODEGEN "${lower_project_name}-optests")
set(IRENE3_CODEGEN
  "${IRENE3_CODEGEN}"
  PARENT_SCOPE
)

add_executable("${IRENE3_CODEGEN}" "Main.cpp")

set_target_properties("${IRENE3_CODEGEN}" PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries("${IRENE3_CODEGEN}" PRIVATE irene3)

if(IRENE3_ENABLE_INSTALL)
  install(
    TARGETS "${IRENE3_CODEGEN}"
    EXPORT irene3Targets
    RUNTIME DESTINATION bin
  )
endif(IRENE3_ENABLE_INSTALL)
