#include "irene3/IreneLoweringInterface.h"
#include "irene3/PatchIR/PatchIRAttrs.h"
#include "irene3/Util.h"

#include <algorithm>
#include <cstdint>
#include <irene3/Targets/Components.h>
#include <irene3/Targets/GenericBackend.h>
#include <iterator>
#include <llvm/CodeGen/MachineValueType.h>
#include <llvm/CodeGen/TargetRegisterInfo.h>
#include <llvm/MC/MCRegister.h>
#include <memory>
#include <mlir/Support/LLVM.h>
#include <optional>
#include <vector>

namespace irene3
{
    namespace
    {
        const std::unordered_map< std::string, std::vector< std::string > >
            allocateableRegClassesForTarget = {
                {   "arm", { "tGPR" }},
                { "thumb", { "tGPR" }},
                {"x86_64", { "GR64" }}
        };

        const std::unordered_map< std::string, std::string > stack_register_names = {
            {    "arm",  "SP"},
            {  "thumb",  "SP"},
            { "x86_64", "RSP"},
            {"powerpc",  "R1"}
        };
    } // namespace

    std::optional< llvm::MCPhysReg > GenericBackend::StackRegister() const {
        auto nm = this->subtarget.getTargetTriple().getArchName().str();
        if (stack_register_names.contains(nm)) {
            return this->supported_registers.lookup(stack_register_names.at(nm));
        }

        return std::nullopt;
    }

    std::vector< llvm::MCPhysReg > GenericBackend::PointerRegs() const {
        const std::vector< std::string >& target_reg_classes = allocateableRegClassesForTarget.at(
            this->subtarget.getTargetTriple().getArchName().str());

        std::vector< llvm::MCPhysReg > res;

        for (auto cls : target_reg_classes) {
            auto ls = this->name_to_register_class.at(cls);
            for (auto r : ls->getRegisters()) {
                res.push_back(r);
            }
        }

        return res;
    }

    bool GenericBackend::IsSupportedValue(mlir::Attribute vop) const {
        if (mlir::isa< patchir::MemoryIndirectAttr >(vop)
            || mlir::isa< patchir::MemoryAttr >(vop)) {
            return true;
        }

        if (auto reg = mlir::dyn_cast< patchir::RegisterAttr >(vop)) {
            return supported_registers.lookup(reg.getReg().str()).has_value();
        }

        return false;
    }

    // TODO(Ian): we arent doing any splitting of high variables just store and load
    // everything one go, we should handle this in other backends
    std::vector< RegionComponentPtr > GenericBackend::LowerValue(mlir::Attribute vop) const {
        if (auto reg = mlir::dyn_cast< patchir::RegisterAttr >(vop)) {
            auto maybe_reg = this->supported_registers.lookup(reg.getReg().str());

            LOG_IF(FATAL, !maybe_reg) << "should have register for: " << reg.getReg().str();
            for (auto r : this->reg_info->regclasses()) {
                LOG(ERROR) << "Has class:" << this->reg_info->getRegClassName(r);
                if (r->contains(*maybe_reg)) {
                    LOG(ERROR) << "Looking in class " << this->reg_info->getRegClassName(r) << " "
                               << r->MC->getSizeInBits() << " target size: " << reg.getSizeBits()
                               << " is subclass " << r->isASubClass();
                    if (r->MC->getSizeInBits() == reg.getSizeBits()) {
                        LOG(ERROR) << "Found in " << this->reg_info->getRegClassName(r);
                        for (llvm::TargetRegisterInfo::vt_iterator st
                             = this->reg_info->legalclasstypes_begin(*r),
                             end = this->reg_info->legalclasstypes_end(*r);
                             st != end; st++) {
                            return { std::make_unique< RegisterComponent >(*st, *maybe_reg) };
                        }
                    }
                }
            }
            LOG(FATAL) << "No correctly sized register found for target size: "
                       << reg.getReg().str() << ":" << reg.getSizeBits();
        } else if (auto stk = mlir::dyn_cast< patchir::MemoryIndirectAttr >(vop)) {
            return { std::make_unique< StackComponent >(
                llvm::MVT::getIntegerVT(stk.getSizeBits()), stk.getOffset()) };
        }

        LOG(FATAL) << "Lowering unsupported value";
    }

} // namespace irene3