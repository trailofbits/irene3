#include <irene3/Targets/Backend.h>
#include <llvm/CodeGen/MachineValueType.h>
#include <map>
#include <optional>
#include <vector>

namespace irene3
{
#include "Backend.inc"

    std::optional< ExplicitMappingBackend > Populate(
        std::string backend_name,
        const llvm::TargetSubtargetInfo &subtarget,
        const llvm::TargetRegisterInfo *reg_inf,
        llvm::LLVMContext &context) {
        if (BackendByName.contains(backend_name)) {
            return ExplicitMappingBackend::Populate(
                BackendByName.at(backend_name), subtarget, reg_inf, context);
        }

        return std::nullopt;
    }
} // namespace irene3