#pragma once

#include <irene3/RegTable.h>
#include <irene3/Util.h>
#include <llvm/CodeGen/MachineValueType.h>
#include <llvm/CodeGen/TargetLowering.h>
#include <llvm/CodeGen/TargetRegisterInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/Target/TargetMachine.h>
#include <unordered_map>
#include <vector>

namespace irene3
{

    struct LowAssignment {
        size_t byte_offset;
        llvm::MVT type;
    };

    class PhysTypeTranslator {
      private:
        RegTable reg_table;
        const llvm::TargetRegisterInfo *reg_info;

      public:
        explicit PhysTypeTranslator(const llvm::TargetRegisterInfo *);

        const RegTable &getRegTable() const { return this->reg_table; }

        std::optional< std::vector< llvm::MVT > > ComputeComponentAssignments(
            llvm::Type *target_type, LowLoc lowloc);
    };
} // namespace irene3