# PatchLang Reference

PatchLang is an s-expression based language for expressing the semantics of patches. The language supports expressing the low-level location of variables and then manipulating those variables with LLVM like statements.

## Modules:
The top-level syntax of patchlang is packaged in a module 

> **<sup>Syntax:<sup>**\
>_Module_:\
> (module \
>  &nbsp;&nbsp; layout: _StrLitExpr_ \
>  &nbsp;&nbsp; triplet: _StrLitExpr_ \
>  &nbsp;&nbsp; image_base: _IntLitExpr_ \
> &nbsp;&nbsp; [[_TDecl_](tdecls.md)]*
> )

### Summary
A module packages together a repeated sequence of ordered top-level declarations. Each declaration is in-scope for the remainder of the module.

### Attribute description

- **layout** is an [LLVM data layout](https://llvm.org/docs/LangRef.html#langref-datalayout) string for the target
- **triplet** is the [LLVM target triplet](https://llvm.org/docs/LangRef.html#target-triple)
- **image_base*** is the base load address of the image that all mentioned virtual addresses are assumed relative to


