# Summary

[Introduction](intro.md)

# General IRENE Usage

- [Installation](./installation.md)
- [Ghidra Plugin Usage](./ghidra/readme.md)
  - [Specifying a Program](./ghidra/specify.md)
  - [GUI Patching](./ghidra/gui.md)
  - [Slicing](./ghidra/slicing.md)
- [Command Line Tool Usage](./cli/readme.md)
  - [Lifting a Specified Block to PatchLang](./cli/irene-lift.md)
  - [Lowering a PatchLang Block to Assembly](./cli/irene-lower.md)
  - [Inserting a Compiled Patch into a Binary](./cli/patch-assembler.md)
  - [Decompiling a Specification to LLVM](./cli/llvm_decomp.md)
  
# PatchLang Reference

- [Introduction](./lang_ref/intro.md)
  - [Top Level Declarations](./lang_ref/tdecls.md)
    - [Type Declaration/Alias](./lang_ref/tdecls/typedecl.md)
    - [External Function](./lang_ref/tdecls/externalfunction.md)
    - [External Global](./lang_ref/tdecls/externalglobal.md)
    - [Function](./lang_ref/tdecls/function.md)
      - [Region](./lang_ref/tdecls/region.md)
    - [Statements](./lang_ref/statements.md)
    - [Expressions](./lang_ref/expressions.md)
    - [Locations](./lang_ref/locations.md)
    - [Types](./lang_ref/types.md)