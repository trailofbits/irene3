#include <iostream>
#include <irene3/IreneLoweringInterface.h>
#include <llvm/IR/CallingConv.h>
#include <llvm/MC/MCRegister.h>
#include <mlir/Target/LLVMIR/TypeToLLVM.h>
#include <optional>
#include <variant>
#include <vector>

using namespace std::placeholders;
namespace irene3
{
    void RegionSignature::addComponent(const std::vector< RegionComponentPtr >& comp) {
        components.push_back(comp);
    }

    const std::vector< std::vector< RegionComponentPtr > >& RegionSignature::Components() const {
        return components;
    }

    bool RegionSignature::AllocateInCC(
        unsigned ValNo,
        llvm::MVT ValVT,
        llvm::MVT LocVT,
        llvm::CCValAssign::LocInfo LocInfo,
        llvm::ISD::ArgFlagsTy ArgFlags,
        llvm::CCState& State) const {
        unsigned idx = 0;
        for (auto& comp : components) {
            for (auto& subcomp : comp) {
                if (ValNo == idx) {
                    return subcomp->AllocateInCC(
                        stack_offset, ValNo, ValVT, LocVT, LocInfo, ArgFlags, State);
                }
                ++idx;
            }
        }
        return true;
    }

    void RegionSignature::dump() const {
        std::cerr << "RegionSignature:" << std::endl;
        for (const auto& comp : components) {
            std::cerr << "Component:" << std::endl;
            for (auto& subc : comp) {
                subc->dump();
                subc->GetMVT().dump();
            }
            std::cerr << "/Component" << std::endl;
        }
        std::cerr << "/RegionSignature" << std::endl;
    }

    void RegionSummary::dump() const {
        std::cerr << "RegionSummary:" << std::endl;
        std::cerr << "at_entry ";
        at_entry.dump();
        std::cerr << "at_exit ";
        at_exit.dump();
        std::cerr << "/RegionSummary" << std::endl;
    }
} // namespace irene3