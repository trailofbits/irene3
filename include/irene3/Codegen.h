/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once
namespace clang
{
    class ASTUnit;
    class CompoundStmt;
} // namespace clang

namespace llvm
{
    class Function;
}

namespace irene3
{
    clang::CompoundStmt *Decompile(llvm::Function &function, clang::ASTUnit &ast_unit);
}