# Expressions

> **<sup>Syntax:<sup>**\
> _Expr_:  
> | _StrLitExpr_
> | _DeclRefExpr_
> | _BinaryExpr_
> | _CastExpr_
> | _GetElementPtrExpr_
> | _CallExpr_
> | _CallIntrinsicExpr_
> | _AllocaExpr_
> | _LoadExpr_
> | _NullExpr_
> | _SelectExpr_
> | _AddrOfExpr_
> | _ConstantOp_




## StrLitExpr

> **<sup>Syntax:<sup>**\
> _StrLitExpr_: "[_AlphaNumericCharacter_|Symbol]*"

### Semantics 

A string of characters,


## DeclRefExpr

> **<sup>Syntax:<sup>**\
> _DeclRefExpr_: _Identifier_

### Semantics 

An expression that refers to some bound identifier.

## BinaryExpr

> **<sup>Syntax:<sup>**\
> _BinaryExpr_: (_BinOp_ _Expr_ _Expr_)

### Semantics

Produces a value by applying the operation to the provided operands.

### BinOp

- `fadd` floating point add
- `fsub` floating point sub
- `fmul` floating point multiplication
- `udiv` unsigned divide
- `sdiv` signed divide
- `fdiv` floating point divide
- `srem` signed remainder
- `frem` floating point remainder
- `lshr` logical shift right
- `ashr` arithmetic shift right
- `and` logical and
- `or` logical or
- `xor` exclusive or
- `eq` equality
- `ne` not equal
- `ugt` unsigned greater than
- `uge` unsigned greater than or equal
- `ult` unsigned less than
- `ule` unsigned less than or equal
- `sgt` signed greater than
- `sge` signed greater than or equal
- `sle` signed less then or equal
- `foeq` floating point equality
- `folt` floating point less than
- `fole` floating point less than or equal
- `fone` floating point not equal
- `ford` ordered, excluding nan
- `fueq` floating point equal allowing nan
- `fugt` floating point greater allowing nan
- `fuge` floating pointer greater or equal allowing nan
- `fult` floating point less than allowing nan
- `fule` floating point less than or equal to allowing nan
- `fune` floating point not equal allowing nan
- `funo` true if either operand is nan


## CastExpr

> **<sup>Syntax:<sup>**\
> _CastExpr_: (_CastOp_ type: _Type_ _Expr_)

### Semantics

Performs a cast to the target type using the specified cast op.


## Cast Ops
- `ptrtoint`: converts a pointer to an int
- `trunc`: truncates an integer
- `zext`: zero extends an integer
- `sext`: sign extends an integer
- `fptrunc`: floating point truncate
- `fpext`: floating point extend
- `fptoui`: converts a floating point value to an unsigned integer
- `fptosi`: converts a floating point value to a signed integer
- `uitofp`: converts an unsigned integer to a floating point value
- `sitofp`: converts a signed integer to a floating point value
- `inttoptr`: converts an integer to a pointer
- `bitcast`: performs a bitcast between types, a value's bits are simply reinterpreted as the new type

## GetElementPtrExpr

> **<sup>Syntax:<sup>**\
> _GetElementPtrExpr_: (getelementptr type: _Expr_ _Type_ [_Expr_]*)

### Semantics

Computes a pointer from a pointer to the type _Type_. Each expression in the list of expressions is an index (either of a field or array). See the [LLVM documentation on GEP](https://llvm.org/docs/GetElementPtr.html) for more information. 

## CallExpr


> **<sup>Syntax:<sup>**\
> _CallExpr_:  (call callee: _StrLitExpr_ [_Expr_]*)

### Semantics

Calls the function with the name `callee` and the provided list of arguments. The return value is the value of the expression.

## IntrinsicExpr

> **<sup>Syntax:<sup>**\
> _IntrinsicExpr_:  (intrinsic callee: _StrLitExpr_ [_Expr_]*)
>

## Semantics

Calls the [LLVM intrinsic](https://llvm.org/docs/LangRef.html#intrinsic-functions) with the name `callee` and the provided list of arguments.


## AllocaExpr

> **<sup>Syntax:<sup>**\
> _AllocaExpr_:  (alloca alignment: _IntLitExpr_ type: _Type_ arraySize: _Expr_)

### Semantics

Allocates a pointer on the stack of size `type*arraySize` with the given alignment.

## LoadExpr

> **<sup>Syntax:<sup>**\
> _LoadExpr_:  (load type: _Type_ _Expr_)

### Semantics

Loads a value of `type` from the given pointer.

## NullExpr

> **<sup>Syntax:<sup>**\
> _NullExpr_:  null


### Semantics

A null pointer of pointer with on the target datalayout.


## SelectExpr

> **<sup>Syntax:<sup>**\
> _SelectExpr_:  (select cond: _Expr_ if_true: _Expr_ if_false: _Expr_)


### Semantics

Returns a value based on `cond`. If cond evaluates to true then the select evaluates to `if_true`, otherwise it evaluates to `if_false`.

## AddrofExpr

> **<sup>Syntax:<sup>**\
> _AddrofExpr_:  (addrof _StrLitExpr_)

### Semantics

Returns a pointer to a named global variable.

## ConstantOp

> **<sup>Syntax:<sup>**\
> _ConstantOp_:  
>  | IntLitExpr | BoolLitExpr | SplatExpr

### Semantics

A constant literal.

## IntLitExpr

> **<sup>Syntax:<sup>**\
> _IntLitExpr_: [+|-]?[digit]+:[digit]+

### Semantics

An integer literal is in the form `<+|->?<value>:<bitsize>`. For instance, `12:32` is an unsigned 12 with a bitwidth of 32 and `+1:32` is a signed 32 bit 1. 

## BoolLitExpr

> **<sup>Syntax:<sup>**\
> _BoolLitExpr_: true | false

### Semantics

A boolean (represented as a 1 bit value) true or false.

## Splat

> **<sup>Syntax:<sup>**\
> _SplatExpr_: (splat type: _Type_ num_elems: _IntLitExpr_ _ConstantOp_)

### Semantics

An array literal that repeats the given constant of `type` `num_elem` times.