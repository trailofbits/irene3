#
# Copyright (c) 2023-present, Trail of Bits, Inc. All rights reserved.
#
# This source code is licensed in accordance with the terms specified in the LICENSE file found in
# the root directory of this source tree.
#

string(TOLOWER "${PROJECT_NAME}" lower_project_name)
set(IRENE3_PATCHLANG2PATCHIR "${lower_project_name}-patchlang2patchir")
set(IRENE3_PATCHLANG2PATCHIR
    "${IRENE3_PATCHLANG2PATCHIR}"
    PARENT_SCOPE
)

add_executable("${IRENE3_PATCHLANG2PATCHIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/Main.cpp"
)
target_include_directories("${IRENE3_PATCHLANG2PATCHIR}" PRIVATE
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
    "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>")
target_link_libraries("${IRENE3_PATCHLANG2PATCHIR}" PRIVATE
    irene3
    PatchIR
    MLIRLLVMDialect
    MLIRLLVMIRToLLVMTranslation)

if(IRENE3_ENABLE_INSTALL)
    install(
        TARGETS "${IRENE3_PATCHLANG2PATCHIR}"
        EXPORT irene3Targets
        RUNTIME DESTINATION bin
    )
endif(IRENE3_ENABLE_INSTALL)