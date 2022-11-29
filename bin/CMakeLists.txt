#
# Copyright (c) 2021-present, Trail of Bits, Inc. All rights reserved.
#
# This source code is licensed in accordance with the terms specified in the LICENSE file found in
# the root directory of this source tree.
#

add_subdirectory("Codegen")
add_subdirectory("Decompile")
add_subdirectory("Kleeable")
add_subdirectory("UITool")
set(IRENE3_DECOMP
    "${IRENE3_DECOMP}"
    PARENT_SCOPE
)
set(IRENE3_CODEGEN
    "${IRENE3_CODEGEN}"
    PARENT_SCOPE
)
