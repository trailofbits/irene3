#include <irene3/IreneLoweringInterface.h>
#include <irene3/Util.h>
#include <llvm/Support/raw_ostream.h>
#include <remill/BC/Util.h>

namespace irene3
{
    class StackComponent : public RegionComponent {
      private:
        std::int64_t flat_offset;

      public:
        StackComponent(llvm::MVT machine_type, std::int64_t flat_offset)
            : RegionComponent(machine_type)
            , flat_offset(flat_offset) {}

        virtual llvm::Value* Load(llvm::IRBuilder<>& bldr, llvm::Value* high_value) const override {
            // TODO(Ian): no conversions we just expect to load the whole thing
            return bldr.CreateLoad(
                ConvertMVT(high_value->getContext(), this->machine_type), high_value);
        }

        // Given a MVT component, stores it
        virtual void Store(
            llvm::IRBuilder<>& bldr, llvm::Argument* arg, llvm::Value* high_value) const override {
            bldr.CreateStore(arg, high_value);
        }

        virtual void dump() override { llvm::errs() << "Stack comp: " << flat_offset; }

        // allocates this component in a calling convention.
        // false is success cause why not
        virtual bool AllocateInCC(
            std::int64_t current_stack_offset,
            unsigned int ValNo,
            llvm::MVT ValVT,
            llvm::MVT LocVT,
            llvm::CCValAssign::LocInfo LocInfo,
            llvm::ISD::ArgFlagsTy ArgFlags,
            llvm::CCState& State) const override {
            LOG(INFO) << "mem indirect";
            // TODO(Ian): https://github.com/trailofbits/irene3/issues/337
            State.addLoc(llvm::CCValAssign::getMem(
                ValNo, ValVT, flat_offset - current_stack_offset, LocVT, LocInfo));
            return false;
        }

        virtual ~StackComponent() = default;
    };

    class RegisterComponent : public RegionComponent {
      private:
        llvm::MCPhysReg physical_register;

      public:
        RegisterComponent(llvm::MVT machine_type, llvm::MCPhysReg phys_reg)
            : RegionComponent(machine_type)
            , physical_register(phys_reg) {}

        virtual llvm::Value* Load(llvm::IRBuilder<>& bldr, llvm::Value* high_value) const override {
            // TODO(Ian): no conversions we just expect to load the whole thing
            return bldr.CreateLoad(
                ConvertMVT(high_value->getContext(), this->machine_type), high_value);
        }
        // TODO(Ian): we arent doing any splitting of high variables just store and load
        // everything one go,
        // Given a MVT component, stores it
        virtual void Store(
            llvm::IRBuilder<>& bldr, llvm::Argument* arg, llvm::Value* high_value) const override {
            bldr.CreateStore(arg, high_value);
        }

        // allocates this component in a calling convention.
        // false is success cause why not
        virtual bool AllocateInCC(
            std::int64_t stack_offset,
            unsigned int ValNo,
            llvm::MVT ValVT,
            llvm::MVT LocVT,
            llvm::CCValAssign::LocInfo LocInfo,
            llvm::ISD::ArgFlagsTy ArgFlags,
            llvm::CCState& State) const override {
            LOG(INFO) << "Allocating " << this->physical_register;
            auto res = State.AllocateReg(physical_register);
            CHECK(res);
            State.addLoc(llvm::CCValAssign::getReg(ValNo, ValVT, res, LocVT, LocInfo));
            return false;
        }

        virtual ~RegisterComponent() = default;
    };
} // namespace irene3