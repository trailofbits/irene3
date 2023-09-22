#include <mlir/Dialect/LLVMIR/LLVMDialect.h>
#include <mlir/IR/DialectImplementation.h>
#include <mlir/IR/OpImplementation.h>

//

#include <irene3/PatchIR/PatchIRAttrs.h>
#include <irene3/PatchIR/PatchIRDialect.h>
#include <irene3/PatchIR/PatchIROps.h>
#include <irene3/PatchIR/PatchIRTypes.h>

#define GET_ATTRDEF_CLASSES
#include <irene3/PatchIR/PatchIRAttrs.cpp.inc>

void irene3::patchir::PatchIRDialect::registerAttrs() {
    addAttributes<
#define GET_ATTRDEF_LIST
#include <irene3/PatchIR/PatchIRAttrs.cpp.inc>
        >();
}