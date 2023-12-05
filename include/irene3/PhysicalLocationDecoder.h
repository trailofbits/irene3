#pragma once

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

    class RegTable {
      public:
        std::unordered_map< std::string, llvm::MCPhysReg > registers;

        std::optional< llvm::MCPhysReg > lookup(const std::string &a) const {
            auto r = this->registers.find(a);
            if (r != this->registers.end()) {
                return r->second;
            }

            return std::nullopt;
        }

        void Populate(const llvm::TargetRegisterInfo *reg_info) {
            for (auto cls : reg_info->regclasses()) {
                for (auto reg : cls->getRegisters()) {
                    auto nm = reg_info->getName(reg);
                    registers.insert({ std::string(nm), reg });
                }
            }
        }
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