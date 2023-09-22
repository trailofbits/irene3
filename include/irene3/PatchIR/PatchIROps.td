#ifndef PATCHIR_OPS
#define PATCHIR_OPS

include "PatchIR.td"
include "PatchIRAttrs.td"
include "mlir/Interfaces/InferTypeOpInterface.td"
include "mlir/Interfaces/SideEffectInterfaces.td"
include "mlir/IR/BuiltinAttributes.td"
include "mlir/Dialect/LLVMIR/LLVMTypes.td"

def PatchIR_FunctionOp : PatchIR_Op<"function",
    [Pure, SameOperandsAndResultType]> {
    let summary = "A function to be patched";
    let description = [{ }];

    let arguments = (ins
        UI64Attr:$address,
        Builtin_StringAttr:$name);
    let results = (outs);

    let regions = (region
        SizedRegion<1>:$body);
}

def PatchIR_RegionOp : PatchIR_Op<"region",
    [Pure, SameOperandsAndResultType]> {
    let summary = "A patch region";
    let description = [{
        A region of size `$size` bytes located at `$address`.
        The stack offset at entry is `$stack_offset_entry` bytes,
        and `$stack_offset_exit` at exit.
    }];

    let arguments = (ins
        UI64Attr:$address,
        UI64Attr:$size_bytes,
        I64Attr:$stack_offset_entry_bytes,
        I64Attr:$stack_offset_exit_bytes);
    let results = (outs);

    let regions = (region
        SizedRegion<1>:$body);
}

def PatchIR_ValueOp : PatchIR_Op<"value", [Pure]> {
    let summary = "A value";
    let description = [{
        The location of the value can change between the entry
        and exit of the region it resides in.
    }];
    let arguments = (ins
        Builtin_StringAttr:$name,
        OptionalAttr<PatchIR_LowLocAttr>:$at_entry,
        OptionalAttr<PatchIR_LowLocAttr>:$at_exit);
    let results = (outs LLVMPointerType);
    let regions = (region);
}

def PatchIR_CallOp : PatchIR_Op<"call"> {
  let summary = "Indicates the LLVM function that contains the code for a region";
  let description = [{ }];

  let arguments = (ins
    FlatSymbolRefAttr:$callee,
    Variadic<LLVMPointerType>:$args);
  let results = (outs);
}

#endif // PATCHIR_OPS