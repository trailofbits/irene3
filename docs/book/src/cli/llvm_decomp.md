# Decompiling a Specification to LLVM

IRENE also provides tooling for directly lifting all specified functions to LLVM. This representation is not directly recompileable, but can be used for analysis, evaluation of semantics etc. 

`irene3-decompile -spec  <spec.pb> -ir_out <file.ll>` will produce an LLVM IR file for the given spec.

There are additional options described in the help menu for limiting the lifted entities.
