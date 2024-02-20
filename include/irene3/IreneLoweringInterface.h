#pragma once

#include <cstdint>
#include <irene3/PatchIR/PatchIROps.h>
#include <llvm/CodeGen/MachineValueType.h>
#include <llvm/CodeGen/TargetRegisterInfo.h>
#include <llvm/IR/Argument.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/MC/CCRegistry.h>
#include <llvm/MC/MCRegister.h>
#include <memory>
#include <mlir/IR/Attributes.h>
#include <optional>
#include <vector>

namespace irene3
{

    // A region interface descibes how to allocate parameters for that region
    class RegionComponent {
      protected:
        llvm::MVT machine_type;

      public:
        RegionComponent(llvm::MVT machine_type)
            : machine_type(machine_type) {}

        virtual llvm::Value* Load(llvm::IRBuilder<>&, llvm::Value* high_value) const = 0;
        // Given a MVT component, stores it
        virtual void Store(llvm::IRBuilder<>&, llvm::Argument* arg, llvm::Value* high_value) const
            = 0;

        // allocates this component in a calling convention.
        virtual bool AllocateInCC(
            std::int64_t stack_offset,
            unsigned int ValNo,
            llvm::MVT ValVT,
            llvm::MVT LocVT,
            llvm::CCValAssign::LocInfo LocInfo,
            llvm::ISD::ArgFlagsTy ArgFlags,
            llvm::CCState& State) const
            = 0;

        virtual void dump() { this->machine_type.dump(); }

        llvm::MVT GetMVT() const { return this->machine_type; }
    };

    using RegionComponentPtr = std::shared_ptr< RegionComponent >;

    class IreneLoweringInterface {
      public:
        virtual std::vector< llvm::MCPhysReg > PointerRegs() const = 0;

        virtual std::optional< llvm::MCPhysReg > StackRegister() const = 0;

        virtual bool IsSupportedValue(mlir::Attribute vop) const                        = 0;
        virtual std::vector< RegionComponentPtr > LowerValue(mlir::Attribute vop) const = 0;

        virtual ~IreneLoweringInterface() = default;
    };

    // A region signature is built from the addition of a value as a component
    class RegionSignature {
      private:
        std::int64_t stack_offset;
        std::vector< std::vector< RegionComponentPtr > > components;

      public:
        RegionSignature(std::int64_t stack_offset)
            : stack_offset(stack_offset) {}

        void addComponent(const std::vector< RegionComponentPtr >& comp);

        const std::vector< std::vector< RegionComponentPtr > >& Components() const;

        bool AllocateInCC(
            unsigned ValNo,
            llvm::MVT ValVT,
            llvm::MVT LocVT,
            llvm::CCValAssign::LocInfo LocInfo,
            llvm::ISD::ArgFlagsTy ArgFlags,
            llvm::CCState& State) const;

        inline bool operator()(
            unsigned ValNo,
            llvm::MVT ValVT,
            llvm::MVT LocVT,
            llvm::CCValAssign::LocInfo LocInfo,
            llvm::ISD::ArgFlagsTy ArgFlags,
            llvm::CCState& State) const {
            return AllocateInCC(ValNo, ValVT, LocVT, LocInfo, ArgFlags, State);
        }

        void dump() const;
    };

    struct RegionSummary {
        RegionSignature at_entry;
        RegionSignature at_exit;

        void dump() const;
    };

} // namespace irene3