#pragma once

#include <llvm/CodeGen/TargetLowering.h>
#include <llvm/CodeGen/TargetRegisterInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/Target/TargetMachine.h>
#include <optional>
#include <unordered_map>

namespace irene3
{
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
} // namespace irene3