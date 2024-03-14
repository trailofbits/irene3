# Introduction

IRENE is a tool for decompilation of subfunction regions of code that can be soundly recompiled and situated into the binary through detouring. After identifying in-scope variable locations, IRENE lifts a basic block or sub basic block region of code to an editable representation that references these variables. The user can then make modifications to this code region. The code region is recompiled and placed in the binary at its original location through a detour to free space.

This book highlights how to [install IRENE](installation.md), how to use irene-decompile to retrieve LLVM representations of functions, how to use IRENE to extract the PatchLang representation of a block (the recompileable decompilation), and how to recompile a PatchLang module to a patched binary. 

Finally, the book provides a grammar and documentation for PatchLang.