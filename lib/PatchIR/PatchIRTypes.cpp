#include <mlir/Dialect/LLVMIR/LLVMDialect.h>
#include <mlir/IR/DialectImplementation.h>
#include <mlir/IR/OpImplementation.h>

//

#include <irene3/PatchIR/PatchIRDialect.h>
#include <irene3/PatchIR/PatchIROps.h>
#include <irene3/PatchIR/PatchIRTypes.h>

#define GET_TYPEDEF_CLASSES
#include <irene3/PatchIR/PatchIRTypes.cpp.inc>

void irene3::patchir::PatchIRDialect::registerTypes() {
    addTypes<
#define GET_TYPEDEF_LIST
#include <irene3/PatchIR/PatchIRTypes.cpp.inc>
        >();
}