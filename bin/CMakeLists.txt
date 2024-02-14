#
# Copyright (c) 2021-present, Trail of Bits, Inc. All rights reserved.
#
# This source code is licensed in accordance with the terms specified in the LICENSE file found in
# the root directory of this source tree.
#

add_subdirectory("Codegen")
add_subdirectory("Decompile")
add_subdirectory("Kleeable")
add_subdirectory("EvalProduceLinkableModule")
add_subdirectory("PatchIRCodegen")
add_subdirectory("PatchLang2PatchIR")
add_subdirectory("PatchCompiler")
add_subdirectory("PatchLangLifter")
add_subdirectory("ExamineSpec")
add_subdirectory("PatchLangServer")

set(IRENE3_DECOMP
    "${IRENE3_DECOMP}"
    PARENT_SCOPE
)
set(IRENE3_CODEGEN
    "${IRENE3_CODEGEN}"
    PARENT_SCOPE
)

if(IRENE3_ENABLE_INSTALL)
    install(
        PROGRAMS
        "${CMAKE_CURRENT_SOURCE_DIR}/irene3-lift"
        "${CMAKE_CURRENT_SOURCE_DIR}/irene3-lower"
        DESTINATION bin
    )
endif(IRENE3_ENABLE_INSTALL)
