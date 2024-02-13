#pragma once

#include <irene3/Targets/ExplicitMappingBackend.h>
namespace irene3
{
    std::optional< ExplicitMappingBackend > Populate(
        std::string backend_name,
        const llvm::TargetSubtargetInfo &subtarget,
        const llvm::TargetRegisterInfo *reg_inf,
        llvm::LLVMContext &context);
} // namespace irene3