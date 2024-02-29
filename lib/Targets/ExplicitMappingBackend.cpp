#include "irene3/PatchIR/PatchIRAttrs.h"
#include "irene3/PhysicalLocationDecoder.h"
#include "irene3/Util.h"

#include <cstdint>
#include <irene3/Targets/ExplicitMappingBackend.h>
#include <llvm/CodeGen/TargetFrameLowering.h>
#include <llvm/CodeGen/TargetRegisterInfo.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/MC/MCRegister.h>
#include <memory>
#include <mlir/Support/LLVM.h>
#include <optional>
#include <unordered_map>
#include <vector>

namespace irene3
{

    std::optional< llvm::MCPhysReg > ExplicitMappingBackend::StackRegister() const {
        return this->stack_reg;
    }

    std::vector< llvm::MCPhysReg > ExplicitMappingBackend::PointerRegs() const {
        return this->pointer_regs;
    }

    std::optional< MappingRecord > ExplicitMappingBackend::GetRegisterRecord(
        patchir::RegisterAttr reg) const {
        auto res = this->register_info.find(reg.getReg().str());
        while (res != this->register_info.end()) {
            if (res->second.IsApplicable(reg)) {
                return res->second;
            }
            res++;
        }

        return std::nullopt;
    }

    bool ExplicitMappingBackend::IsSupportedValue(mlir::Attribute vop) const {
        if (mlir::isa< patchir::MemoryIndirectAttr >(vop)
            || mlir::isa< patchir::MemoryAttr >(vop)) {
            return true;
        }

        if (auto reg = mlir::dyn_cast< patchir::RegisterAttr >(vop)) {
            LOG(INFO) << "Looking at reg: " << reg.getReg().str();
            return this->GetRegisterRecord(reg).has_value();
        }

        return false;
    }

    std::vector< RegionComponentPtr > ExplicitMappingBackend::LowerValue(
        mlir::Attribute vop) const {
        if (auto reg = mlir::dyn_cast< patchir::RegisterAttr >(vop)) {
            auto reg_record = this->GetRegisterRecord(reg);
            LOG_IF(FATAL, !reg_record)
                << "Should have record, because if unsupported should have been removed by pass: "
                << reg.getReg().str();
            return { reg_record->GetRegComp(reg.getSizeBits()) };
        } else if (auto stk = mlir::dyn_cast< patchir::MemoryIndirectAttr >(vop)) {
            return { std::make_unique< StackComponent >(
                llvm::MVT::getIntegerVT(stk.getSizeBits()), stk.getOffset(), this->lao_offset) };
        }
        LOG(FATAL) << "Unsupported value attribute";
    }

    bool MappingRecord::IsApplicable(patchir::RegisterAttr reg) const {
        return this->applicable_types.contains(reg.getSizeBits());
    }

    std::unique_ptr< RegisterComponent > MappingRecord::GetRegComp(size_t ind) const {
        if (!this->applicable_types.contains(ind)) {
            return nullptr;
        } else {
            return std::make_unique< RegisterComponent >(this->applicable_types.at(ind));
        }
    }

    ExplicitMappingBackend ExplicitMappingBackend::Populate(
        const BackendInfo& mapping,
        const llvm::TargetSubtargetInfo& subtarget,
        const llvm::TargetRegisterInfo* reg_info,
        llvm::LLVMContext& context) {
        std::vector< llvm::MCPhysReg > pointer_regs;
        RegTable tbl;
        tbl.Populate(reg_info);

        for (auto rc : mapping.pointer_regs) {
            auto r = tbl.lookup(rc);
            CHECK(r);
            pointer_regs.push_back(*r);
        }

        std::multimap< std::string, MappingRecord > register_info;
        for (auto insert : mapping.mapping) {
            auto tgt_reg = insert.from;
            std::unordered_map< size_t, RegisterComponent > comps;
            auto to_reg = tbl.lookup(insert.to);
            CHECK(to_reg);
            auto comp = RegisterComponent(insert.res_ty, *to_reg);
            for (auto app_ty : insert.applyto) {
                comps.insert({ app_ty.getFixedSizeInBits(), comp });
            }
            register_info.insert({ tgt_reg, MappingRecord(tgt_reg, comps) });
        }

        auto sreg = mapping.stack_reg ? tbl.lookup(*mapping.stack_reg) : std::nullopt;

        return ExplicitMappingBackend(
            std::move(register_info), std::move(pointer_regs), sreg,
            subtarget.getFrameLowering()->getOffsetOfLocalArea());
    }

    ExplicitMappingBackend::ExplicitMappingBackend(
        std::multimap< std::string, MappingRecord > register_info,
        std::vector< llvm::MCPhysReg > pointer_regs,
        std::optional< llvm::MCPhysReg > stack_reg,
        std::int64_t lao_offset)
        : register_info(std::move(register_info))
        , pointer_regs(std::move(pointer_regs))
        , stack_reg(stack_reg)
        , lao_offset(lao_offset) {}

} // namespace irene3