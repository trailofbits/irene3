#ifndef PATCHIR_OPS
#define PATCHIR_OPS

include "PatchIR.td"
include "PatchIRAttrs.td"
include "mlir/Interfaces/InferTypeOpInterface.td"
include "mlir/Interfaces/SideEffectInterfaces.td"
include "mlir/IR/BuiltinAttributes.td"
include "mlir/Dialect/LLVMIR/LLVMTypes.td"
include "mlir/IR/OpBase.td"
include "mlir/IR/SymbolInterfaces.td"

def OneRegion: NativeOpTrait<"OneRegion">;

def PatchIR_FunctionOp : PatchIR_Op<"function",
    [OneRegion, Pure, NoTerminator]> {
    let summary = "A function to be patched";
    let description = [{ }];

    let arguments = (ins
        UI64Attr:$address,
        SI64Attr: $disp,
        BoolAttr:$is_external,
        Builtin_StringAttr:$name);
    let results = (outs);

    let regions = (region
     //   SizedRegion<1>:$func_entry,
        MaxSizedRegion<1>:$body
      //  SizedRegion<1>:$func_exit
    );
}

def PatchIR_RegionOp : PatchIR_Op<"region",
    [OneRegion, Pure]> {
    let summary = "A patch region";
    let description = [{
        A region of size `$size` bytes located at `$address`.
        The stack offset at entry is `$stack_offset_entry` bytes,
        and `$stack_offset_exit` at exit.
    }];

    let arguments = (ins
        UI64Attr:$address,
        UI64Attr:$uid,
        UI64Attr:$size_bytes,
        SI64Attr:$stack_offset_entry_bytes,
        SI64Attr:$stack_offset_exit_bytes);
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
    let results = (outs PatchIRPtr);
    let regions = (region);
}

def PatchIR_CallOp : PatchIR_Op<"call", [Terminator]> {
  let summary = "Indicates the LLVM function that contains the code for a region";
  let description = [{ }];

  let arguments = (ins
    FlatSymbolRefAttr:$callee,
    Variadic<PatchIRPtr>:$args);
  let results = (outs);
}

def PatchIR_Global : PatchIR_Op<"global", []> {
      let summary = "Indicates the LLVM function that contains the code for a region";
  let description = [{ }];

  let arguments = (ins StrAttr:$target_sym_name,  OptionalAttr<StrAttr>:$sym_visibility, PatchIR_MemoryAttr:$mem, TypeAttr:$high_type);
  let results = (outs);
}

#endif // PATCHIR_OPS