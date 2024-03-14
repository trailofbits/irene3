# Locations

> **<sup>Syntax:<sup>**\
> _Location_:  
> | _RegLoc_
> | _MemoryIndLoc_
> | _MemoryLoc_

## RegLoc


> **<sup>Syntax:<sup>**\
> _RegLoc_: (register name: IdentifierExt size: IntLitExpr)

### Semantics

The register named by the identifier `name` of bit size `size`.


## MemoryIndLoc


> **<sup>Syntax:<sup>**\
> _MemoryIndLoc_: (memory_indirect base: IdentifierExt offset: IntLitExpr size: IntLitExpr)

### Semantics

Addresses a variable located at `*[base + offset]` of size `size`.

## MemoryLoc

> **<sup>Syntax:<sup>**\
> _MemoryLoc_: (memory address: IntLitExpr size: IntLitExpr displacement: IntLitExpr is_external: BoolLitExpr)

### Semantics

A global location in memory at virtual address `address`. This location can represent and external by setting is_external to true which then computes the address as *[address]+displacement.


