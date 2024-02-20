#pragma once
#include "irene3/PatchIR/PatchIROps.h"

#include <cstdint>
#include <irene3/IreneLoweringInterface.h>

namespace irene3
{

    template< typename T >
    class ILIMixin {
      protected:
        RegionSummary LowerVariables(patchir::CallOp cop) {
            RegionSignature entry(this->CallOpToStackOffset(cop, true));
            RegionSignature exit(this->CallOpToStackOffset(cop, false));
            size_t high_index = 0;
            for (auto arg : cop.getArgs()) {
                auto attr                                 = arg.getDefiningOp();
                auto vop                                  = mlir::cast< patchir::ValueOp >(attr);
                patchir::LowValuePointerType wrapper_type = vop.getType();
                auto highty = static_cast< T* >(this)->type_decoder.translateType(
                    wrapper_type.getElement());
                if (vop.getAtEntry()) {
                    entry.addComponent(this->LowerVariable(*vop.getAtEntry(), high_index, highty));
                } else {
                    entry.addComponent({});
                }
                if (vop.getAtExit()) {
                    exit.addComponent(this->LowerVariable(*vop.getAtExit(), high_index, highty));
                } else {
                    exit.addComponent({});
                }
                high_index += 1;
            }

            return { entry, exit };
        }

        std::int64_t CallOpToStackOffset(const patchir::CallOp& cop, bool is_entry) const {
            auto reg = cop->getParentOfType< patchir::RegionOp >();
            if (is_entry) {
                return reg.getStackOffsetEntryBytes();
            } else {
                return reg.getStackOffsetExitBytes();
            }
        }

        std::vector< RegionComponentPtr > LowerVariable(
            mlir::Attribute attr, size_t hv_index, llvm::Type* high_ty) {
            return static_cast< T* >(this)->ILI.LowerValue(attr);
        }
    };
} // namespace irene3