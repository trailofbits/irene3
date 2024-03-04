#include <irene3/IreneLoweringInterface.h>
#include <irene3/Util.h>
#include <llvm/Support/raw_ostream.h>
#include <remill/BC/Util.h>

namespace irene3
{
    class StackComponent : public RegionComponent {
      private:
        std::int64_t flat_offset;
        std::int64_t lao_offset;

      public:
        StackComponent(llvm::MVT machine_type, std::int64_t flat_offset, std::int64_t lao_offset)
            : RegionComponent(machine_type)
            , flat_offset(flat_offset)
            , lao_offset(lao_offset) {}

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
            LOG(INFO) << "mem indirect off: " << flat_offset
                      << " current_offset: " << current_stack_offset;
            // TODO(Ian): https://github.com/trailofbits/irene3/issues/337
            State.addLoc(llvm::CCValAssign::getMem(
                ValNo, ValVT, (flat_offset - current_stack_offset) + this->lao_offset, LocVT,
                LocInfo));
            return false;
        }

        virtual ~StackComponent() = default;
    };

    class RegisterComponent : public RegionComponent {
      private:
        llvm::MCPhysReg physical_register;
        llvm::MVT applied_to;

      public:
        RegisterComponent(llvm::MVT machine_type, llvm::MCPhysReg phys_reg, llvm::MVT applied_to)
            : RegionComponent(machine_type)
            , physical_register(phys_reg)
            , applied_to(applied_to) {}

        // the idea of a register component is it maps an mvt into an another mvt for a given byte
        // offset, this does not support composites we should have a composite component to support
        // reg by value structs.

        // instead of returning a vector of components we should return a single component for an HV
        // and that comp may be a composite.
        virtual llvm::Value* Load(llvm::IRBuilder<>& bldr, llvm::Value* high_value) const override {
            auto output_type     = ConvertMVT(high_value->getContext(), this->machine_type);
            auto applicable_type = ConvertMVT(high_value->getContext(), this->applied_to);
            auto hv              = bldr.CreateLoad(applicable_type, high_value);

            // it's very explicit that we dont allow <-> conversions on anyting but integer mvt
            // mappings
            if (applicable_type != output_type && hv->getType()->isIntegerTy()
                && output_type->isIntegerTy()) {
                return bldr.CreateZExtOrTrunc(hv, output_type);
            } else {
                return hv;
            }
        }
        // TODO(Ian): we arent doing any splitting of high variables just store and load
        // everything one go,
        // Given a MVT component, stores it
        virtual void Store(
            llvm::IRBuilder<>& bldr, llvm::Argument* arg, llvm::Value* high_value) const override {
            auto output_type      = ConvertMVT(high_value->getContext(), this->machine_type);
            auto applicable_type  = ConvertMVT(high_value->getContext(), this->applied_to);
            llvm::Value* to_store = arg;
            if (output_type != applicable_type && to_store->getType()->isIntegerTy()
                && applicable_type->isIntegerTy()) {
                to_store = bldr.CreateZExtOrTrunc(to_store, applicable_type);
            }
            bldr.CreateStore(to_store, high_value);
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