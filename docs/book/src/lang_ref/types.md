# Types

> **<sup>Syntax:<sup>**\
> _Type_:
> | i8 | i16 | i32 | i64 | i128 | f32 |f64 | ptr | void
> | (struct [_Type_]+)
> | (array size: _IntLitExpr_ type: _Type_)
> | (vector size: _IntLitExpr_ type: _Type_)

## Primitive Types

Integer types are prefixed by an i and followed by the bitwidth. Float types are prefixed by an f. `ptr` is an opaque pointer. `void` is a void type. 

## Struct Types

A struct type is a non-empty collection of types accessed by field indeces in order.

## Array Types

An array with element type `type` and of size `size`.

## Vector Types

A vector type with element type `type` and of size `size`