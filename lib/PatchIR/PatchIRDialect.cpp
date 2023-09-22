#include <mlir/IR/DialectImplementation.h>
#include <mlir/IR/OpImplementation.h>

//

#include <irene3/PatchIR/PatchIRDialect.h>
#include <irene3/PatchIR/PatchIROps.h>
#include <irene3/PatchIR/PatchIRTypes.h>

using namespace mlir;

namespace irene3::patchir
{

    void PatchIRDialect::initialize() {
        registerTypes();
        registerAttrs();

        addOperations<
#define GET_OP_LIST
#include <irene3/PatchIR/PatchIR.cpp.inc>
            >();
    }

} // namespace irene3::patchir

#include <irene3/PatchIR/PatchIRDialect.cpp.inc>