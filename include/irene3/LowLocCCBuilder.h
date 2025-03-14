#pragma once

#include <cstdint>
#include <iostream>
#include <irene3/ILIMixin.h>
#include <irene3/IreneLoweringInterface.h>
#include <irene3/PhysicalLocationDecoder.h>
#include <irene3/Util.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/MC/CCRegistry.h>
#include <llvm/MC/MCRegister.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/TargetRegistry.h>
#include <mlir/Target/LLVMIR/TypeToLLVM.h>
#include <vector>

namespace irene3
{

    class AssignFromLowLocs {
      private:
        llvm::MCPhysReg getRegister(const irene3::patchir::RegisterAttr &reg);

      public:
        AssignFromLowLocs(std::vector< LowLoc > locs, std::int64_t current_stack_offset)
            : locs(std::move(locs))
            , current_stack_offset(current_stack_offset) {}

        void dump();

        bool CCAssignFn(
            unsigned ValNo,
            llvm::MVT ValVT,
            llvm::MVT LocVT,
            llvm::CCValAssign::LocInfo LocInfo,
            llvm::ISD::ArgFlagsTy ArgFlags,
            llvm::CCState &State);

      private:
        std::vector< LowLoc > locs;
        std::int64_t current_stack_offset;
        RegTable table;
    };

    class CCBuilder {
      public:
        std::function< llvm::CCAssignFn > BuidCCAssign(bool isReturn);

        CCBuilder(RegionSummary summary)
            : summary(summary) {
            // this->dump();
        }

        void dump() const;

        const RegionSummary &GetRegionSummary() const;

      private:
        RegionSummary summary;
    };

    class ModuleCallingConventions : public ILIMixin< ModuleCallingConventions > {
        friend class ILIMixin< ModuleCallingConventions >;

      public:
        ModuleCallingConventions(
            mlir::ModuleOp mop, const IreneLoweringInterface &ILI, llvm::LLVMContext &context);

        void Populate(mlir::ModuleOp mop);

        void ApplyTo(llvm::Module *mod);

        uint64_t AddNamedCC(std::string name, CCBuilder builder);

        uint64_t AddCC(CCBuilder builder);

        std::unordered_map< uint64_t, CCBuilder > BuildCConvMap();

        void dump() const;

      protected:
        const IreneLoweringInterface &ILI;
        mlir::LLVM::TypeToLLVMIRTranslator type_decoder;

      private:
        // ordered map for ids
        std::vector< std::pair< std::optional< std::string >, CCBuilder > > builders;
    };

    class CCObjSelector final : public llvm::CCObj {
      private:
        std::unordered_map< uint64_t, CCBuilder > builders;

      public:
        CCObjSelector(std::unordered_map< uint64_t, CCBuilder > builders);

        virtual std::function< llvm::CCAssignFn > CCAssignFnForNode(
            llvm::CallingConv::ID CC, bool Return, bool isVarArg) override;

        virtual bool isTailCallEquiv(llvm::CallingConv::ID) override;

        virtual std::optional< const llvm::MCPhysReg * > getCalleeSaves(
            const llvm::MachineFunction *M) override;

        virtual std::optional< const uint32_t * > getCallPreservedMask(
            const llvm::MachineFunction &M, llvm::CallingConv::ID) override;

        void dump() const;
    };

} // namespace irene3