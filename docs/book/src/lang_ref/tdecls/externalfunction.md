# External Function

> **<sup>Syntax:<sup>**\
>_ExternalFunction_: \
> (external \
>   &nbsp;&nbsp;  address:  [_IntLitExpr_](../expressions.md#IntLitExpr) name: [_ExtIdExpr_](../expressions.md#ExtIdExpr) displacement: [_IntLitExpr_](../expressions.md#IntLitExpr) is_external: [_BoolLitExpr_](../expressions.md#BoolLitExpr)  \
>  &nbsp;&nbsp; [_Type_](../types.md) [[_Type_](../types.md)]*)

## Semantics

An external function declares a callable name with the result type provided and an optional sequence of argument types. The address is a virtual address, which will be computed by the compiler in two modes depending on the is_external flag. If is_external is false, the function called will be at address `(address-original_base_address) + runtime_base_address`. Otherwise, the address will be: `*(address-original_base_address)+displacement`. This indirect call mechanism is used for GOT entries etc.
