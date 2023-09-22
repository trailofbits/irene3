#pragma once

#include <llvm/ADT/Hashing.h>
#include <llvm/ADT/TypeSwitch.h>
#include <mlir/IR/Builders.h>
#include <mlir/IR/Dialect.h>
#include <mlir/IR/MLIRContext.h>
#include <mlir/IR/TypeSupport.h>
#include <mlir/IR/Types.h>

#define GET_TYPEDEF_CLASSES
#include <irene3/PatchIR/PatchIRTypes.h.inc>