#
# Copyright (c) 2021-present, Trail of Bits, Inc. All rights reserved.
#
# This source code is licensed in accordance with the terms specified in the LICENSE file found in
# the root directory of this source tree.
#

string(TOLOWER "${PROJECT_NAME}" lower_project_name)
set(IRENE3_EVAL_TOOL "${lower_project_name}-eval-tool")
set(IRENE3_EVAL_TOOL
  "${IRENE3_EVAL_TOOL}"
  PARENT_SCOPE
)

add_executable("${IRENE3_EVAL_TOOL}" "Main.cpp")

set_target_properties("${IRENE3_EVAL_TOOL}" PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries("${IRENE3_EVAL_TOOL}" PRIVATE irene3)

if(IRENE3_ENABLE_INSTALL)
  install(
    TARGETS "${IRENE3_EVAL_TOOL}"
    EXPORT irene3Targets
    RUNTIME DESTINATION bin
  )
endif(IRENE3_ENABLE_INSTALL)
