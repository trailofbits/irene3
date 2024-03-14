# Function

> **<sup>Syntax:<sup>**\
>_Function_: \
> (function \
>   &nbsp;&nbsp;  address:  [_IntLitExpr_](../expressions.md#IntLitExpr) name: [_ExtIdExpr_](../expressions.md#ExtIdExpr) displacement: [_IntLitExpr_](../expressions.md#IntLitExpr) is_external: [_BoolLitExpr_](../expressions.md#BoolLitExpr)  \
>  &nbsp;&nbsp; [[_Region_](./region.md)]*)

## Semantics

Defines a function with a body of regions. The address is a virtual address. is_external will always be zero. Regions define a collection of control flow free fragments of code that make up the function. Each region has an address and a size, regions should be non-overlapping (zero byte blocks do not overlap with blocks at the same address because they are of zero size).
