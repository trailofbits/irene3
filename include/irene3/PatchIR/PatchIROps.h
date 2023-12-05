#pragma once

#include <irene3/PatchIR/PatchIRAttrs.h>
#include <irene3/PatchIR/PatchIRTypes.h>
#include <mlir/Dialect/LLVMIR/LLVMTypes.h>
#include <mlir/IR/BuiltinTypes.h>
#include <mlir/IR/Dialect.h>
#include <mlir/IR/OpDefinition.h>
#include <mlir/Interfaces/InferTypeOpInterface.h>
#include <mlir/Interfaces/SideEffectInterfaces.h>

#define GET_OP_CLASSES
#include <irene3/PatchIR/PatchIR.h.inc>