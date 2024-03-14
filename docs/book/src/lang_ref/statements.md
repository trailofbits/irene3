# Statements

> **<sup>Syntax:<sup>**\
> _Statement_:  
> | _ValueStmt_
> | _LetStmt_
> | _CallStmt_
> | _IntrinsicStmt_
> | _StoreStmt_
> | _GotoStmt_
> | _CondGotoStmt_
> | _NopStmt_
> | _WhileStmt_
> | _IfStmt_

## ValueStmt

> **<sup>Syntax:<sup>**\
> _ValueStmt_:  (value _IdExpr_ [at_entry: _LowLocation_]? [at_exit: _LowLocation_]?)

### Semantics

Binds a low location to a name. This variable is then available as a pointer for the rest of the statements in the region. If the at_entry location is set then the value will be populated at entry to the region by the current low location. If the at_exit location is set then the low location will be set to the value in the variable at exit from the region. 

## LetStmt

> **<sup>Syntax:<sup>**\
> _LetStmt_:  (let _IdExpr_ _Expr_)

### Semantics

Binds the result of evaluating an expression to a name.

## CallStmt

> **<sup>Syntax:<sup>**\
> _CallStmt_:  (call callee: _StrLitExpr_ [_Expr_]*)

### Semantics

Calls the function with the name `callee` and the provided list of arguments.

## IntrinsicStmt

> **<sup>Syntax:<sup>**\
> _IntrinsicStmt_:  (intrinsic callee: _StrLitExpr_ [_Expr_]*)

### Semantics

Calls the [LLVM intrinsic](https://llvm.org/docs/LangRef.html#intrinsic-functions) with the name `callee` and the provided list of arguments.

## StoreStmt

> **<sup>Syntax:<sup>**\
> _StoreStmt_:  (store [is_volatile: _BoolLitExpr_]* _Expr_ _Expr_)

### Semantics

An LLVM store of a value into a pointer (the second expression argument). is_volatile is an optional boolean attribute signaling a volatile store.

## GotoStmt

> **<sup>Syntax:<sup>**\
> _GotoStmt_:  (goto _IntLitExpr_)

### Semantics

Exits the region and jumps to a virtual address. If the instructions at that address was moved as the result of a detour, the jump will goto the new address for those instructions. 

## CondGotoStmt

> **<sup>Syntax:<sup>**\
> _CondGotoStmt_:  (cond_goto _IntLitExpr_ _Expr_)

## Semantics

Will perform a goto when the provided expression evaluates to true.

## NopStmt

> **<sup>Syntax:<sup>**\
> _NopStmt_:  (nop )

### Semantics

Does nothing.

## WhileStmt

> **<sup>Syntax:<sup>**\
> _WhileStmt_:  (while _Expr_  ([Statement]*))

### Semantics

Executes the body of statements while the boolean expression evaluates to true.

## IfStmt

> **<sup>Syntax:<sup>**\
> _IfStmt_:  (if _Expr_  ([Statement]*) ([Statement]*))

### Semantics

Executes the first list of statements if the expression evaluates to true, otherwise executes the second list of statements.

