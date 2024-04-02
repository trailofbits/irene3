#pragma once

#include "irene3/PhysicalLocationDecoder.h"

#include <irene3/IreneLoweringInterface.h>
#include <llvm/CodeGen/TargetSubtargetInfo.h>
#include <llvm/MC/MCRegister.h>
namespace irene3
{
    class GenericBackend : public IreneLoweringInterface {
      private:
        const llvm::TargetSubtargetInfo& subtarget;
        const llvm::TargetRegisterInfo* reg_info;
        std::unordered_map< std::string, const llvm::TargetRegisterClass* > name_to_register_class;
        RegTable supported_registers;

      public:
        GenericBackend(const llvm::TargetSubtargetInfo& subtarget)
            : subtarget(subtarget)
            , reg_info(subtarget.getRegisterInfo()) {
            for (auto rc : this->reg_info->regclasses()) {
                this->name_to_register_class.insert({ this->reg_info->getRegClassName(rc), rc });
            }

            supported_registers.Populate(this->reg_info);
        }

        virtual std::optional< llvm::MCPhysReg > PhysRegForValue(
            irene3::patchir::RegisterAttr reg, const RegTable& tbl) const override;

        virtual std::optional< llvm::MCPhysReg > StackRegister() const override;
        virtual std::vector< llvm::MCPhysReg > PointerRegs() const override;
        virtual bool IsSupportedValue(mlir::Attribute vop) const override;
        virtual std::vector< RegionComponentPtr > LowerValue(mlir::Attribute vop) const override;
    };
} // namespace irene3