#ifndef PATCHIR_ATTRS
#define PATCHIR_ATTRS

include "PatchIR.td"

include "mlir/IR/BuiltinAttributes.td"

def PatchIR_RegisterAttr : PatchIR_Attr<"Register", "register"> {
    let summary = "The location of a value that exists in a register";
    let description = [{
        The value exists in the register `$reg` and is `$size_bits` wide
    }];
    let parameters = (ins
        Builtin_StringAttr:$reg,
        "uint64_t":$size_bits);

    let assemblyFormat = [{ $reg `:` $size_bits }];
}

def PatchIR_MemoryAttr : PatchIR_Attr<"Memory", "memory"> {
    let summary = "The location of a value that exists in memory";
    let description = [{
        The value exists at address `$addr` and is `$size_bits` wide
    }];
    let parameters = (ins
        "int64_t":$addr,
        "uint64_t":$size_bits);

    let assemblyFormat = [{ `[` $addr `]` `:` $size_bits }];
}

def PatchIR_MemoryIndirectAttr : PatchIR_Attr<"MemoryIndirect", "memory.indirect"> {
    let summary = "The location of a value that exists in memory at an address derived from a register";
    let description = [{
        The value exists at address `[$base + $offset]` and is `$size_bits` wide
    }];
    let parameters = (ins
        Builtin_StringAttr:$base,
        "int64_t":$offset,
        "uint64_t":$size_bits);

    let assemblyFormat = [{ `[` $base `+` $offset `]` `:` $size_bits }];
}

def PatchIR_LowLocAttr : AnyAttrOf<[
    PatchIR_RegisterAttr,
    PatchIR_MemoryAttr,
    PatchIR_MemoryIndirectAttr ]>;

#endif // PATCHIR_ATTRS