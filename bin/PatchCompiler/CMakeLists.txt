#
# Copyright (c) 2023-present, Trail of Bits, Inc. All rights reserved.
#
# This source code is licensed in accordance with the terms specified in the LICENSE file found in
# the root directory of this source tree.
#

# --- CLI compiler tool
string(TOLOWER "${PROJECT_NAME}" lower_project_name)
set(IRENE3_PATCHCOMPILER "${lower_project_name}-patchir-compiler")
set(IRENE3_PATCHCOMPILER
    "${IRENE3_PATCHCOMPILER}"
    PARENT_SCOPE
)

add_executable("${IRENE3_PATCHCOMPILER}" Main.cpp)

set_target_properties("${IRENE3_PATCHCOMPILER}" PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries("${IRENE3_PATCHCOMPILER}" PRIVATE irene3 PatchIR MLIRLLVMDialect MLIRLLVMIRToLLVMTranslation)
target_include_directories(
    "${IRENE3_PATCHCOMPILER}" PRIVATE
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
    "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>"
)

if(IRENE3_ENABLE_INSTALL)
    install(
        TARGETS "${IRENE3_PATCHCOMPILER}"
        EXPORT irene3Targets
        RUNTIME DESTINATION bin
    )
endif(IRENE3_ENABLE_INSTALL)
