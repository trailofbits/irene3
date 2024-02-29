#pragma once

// A target deriving from an explicit mapping backend provides explicit register name -> register
// bindings that support conversions as needed between ghidra etc

#include "irene3/IreneLoweringInterface.h"
#include "irene3/PatchIR/PatchIRAttrs.h"

#include <cstdint>
#include <irene3/Targets/Components.h>
#include <llvm/CodeGen/TargetRegisterInfo.h>
#include <llvm/CodeGen/TargetSubtargetInfo.h>
#include <llvm/IR/Type.h>
#include <llvm/MC/MCRegister.h>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace irene3
{
    struct InputMapping {
        std::string from;
        std::string to;
        std::vector< llvm::MVT > applyto;
        llvm::MVT res_ty;
    };

    struct BackendInfo {
        std::vector< std::string > pointer_regs;
        std::vector< InputMapping > mapping;
        std::optional< std::string > stack_reg;
    };

    class MappingRecord {
      private:
        std::string target_register;
        std::unordered_map< size_t, RegisterComponent > applicable_types;

      public:
        MappingRecord(
            std::string target_register,
            std::unordered_map< size_t, RegisterComponent > applicable_types)
            : target_register(target_register)
            , applicable_types(applicable_types) {}
        bool IsApplicable(patchir::RegisterAttr reg) const;

        std::unique_ptr< RegisterComponent > GetRegComp(size_t) const;
    };

    class ExplicitMappingBackend : public IreneLoweringInterface {
      private:
        std::multimap< std::string, MappingRecord > register_info;
        std::vector< llvm::MCPhysReg > pointer_regs;
        std::optional< llvm::MCPhysReg > stack_reg;
        std::int64_t lao_offset;

      private:
        std::optional< MappingRecord > GetRegisterRecord(patchir::RegisterAttr reg) const;

      public:
        ExplicitMappingBackend(
            std::multimap< std::string, MappingRecord > register_info,
            std::vector< llvm::MCPhysReg > pointer_regs,
            std::optional< llvm::MCPhysReg > stack_register,
            std::int64_t lao_offset);

        virtual std::optional< llvm::MCPhysReg > StackRegister() const override;
        virtual std::vector< llvm::MCPhysReg > PointerRegs() const override;
        virtual bool IsSupportedValue(mlir::Attribute vop) const override;
        virtual std::vector< RegionComponentPtr > LowerValue(mlir::Attribute vop) const override;
        virtual ~ExplicitMappingBackend() = default;
        static ExplicitMappingBackend Populate(
            const BackendInfo& mapping,
            const llvm::TargetSubtargetInfo& subtarget,
            const llvm::TargetRegisterInfo* reg_info,
            llvm::LLVMContext& context);
    };
} // namespace irene3