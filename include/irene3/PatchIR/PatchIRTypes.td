#ifndef PATCHIR_TYPES
#define PATCHIR_TYPES

include "mlir/Interfaces/InferTypeOpInterface.td"
include "mlir/Interfaces/SideEffectInterfaces.td"
include "mlir/IR/BuiltinAttributes.td"
include "mlir/Dialect/LLVMIR/LLVMTypes.td"
include "PatchIR.td"


def PatchIRPtr :  PatchIR_Type<"LowValuePointer", "low.pointer", []> {
    let summary = [{An llvm convertible pointer that sores into a low level location. Unlike an llvm pointer there is some
    high type associated with the pointer.}];

    let parameters = (ins "mlir::Type":$element );

    let assemblyFormat = "`ptr` `<` $element`>`";
}

#endif // PATCHIR_TYPES