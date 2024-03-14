# Region
> **<sup>Syntax:<sup>**\
> _RefOffset_ : ([_IntLitExpr_](../expressions.md#IntLitExpr)  [[_RegExpr_](../expressions.md#RegExpr)]) \
>_Region_: \
> (region \
>   &nbsp;&nbsp;  address:  [_IntLitExpr_](../expressions.md#IntLitExpr) size: [_IntLitExpr_](../expressions.md#IntLitExpr) stack_offset_at_entry
> [_IntLitExpr_](../expressions.md#IntLitExpr) stack_offset_at_exit: [_IntLitExpr_](../expressions.md#IntLitExpr) \
>  &nbsp;&nbsp; reg_stack_offsets_entry: [_RegOffset_]*  reg_stack_offsets_exit: [_RegOffset_]*  \
>  &nbsp;&nbsp; [[_Statement_](../statements.md)]*)

## Semantics

A region is a block of code to be recompiled and replaced. The region's attributes define its location, size, and stack information. The statements define the available variables and code that manipulates them.