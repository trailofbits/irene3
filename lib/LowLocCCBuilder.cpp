#include <irene3/LowLocCCBuilder.h>
#include <llvm/IR/CallingConv.h>
#include <llvm/MC/MCRegister.h>
#include <mlir/Target/LLVMIR/TypeToLLVM.h>
#include <optional>
#include <variant>
#include <vector>

using namespace std::placeholders;
namespace irene3
{
    llvm::MCPhysReg AssignFromLowLocs::getRegister(const irene3::patchir::RegisterAttr &reg) {
        auto regname = reg.getReg().str();
        std::transform(regname.begin(), regname.end(), regname.begin(), ::toupper);

        auto tgt_reg = this->table.lookup(regname);
        LOG_IF(FATAL, !tgt_reg.has_value()) << "Expected reg for: " << regname;
        return *tgt_reg;
    }

    void AssignFromLowLocs::dump() {
        std::cerr << "AssignFromLowLocs: " << std::endl;
        for (auto &v : this->locs) {
            std::visit([](const auto &attr) { attr.dump(); }, v);
        } // namespace irene3
        std::cerr << "/AssignFromLowLocs: " << std::endl;
    }

    bool AssignFromLowLocs::CCAssignFn(
        unsigned ValNo,
        llvm::MVT ValVT,
        llvm::MVT LocVT,
        llvm::CCValAssign::LocInfo LocInfo,
        llvm::ISD::ArgFlagsTy ArgFlags,
        llvm::CCState &State) {
        if (ValNo >= locs.size()) {
            LOG(ERROR) << "ValNo greater than the number of locs: " << ValNo << " has size "
                       << locs.size();
            return true;
        }

        // TODO(Ian): in-effecient can probably do something gross like cache here
        const auto &MF = State.getMachineFunction();
        this->table.Populate(MF.getSubtarget().getRegisterInfo());
        LOG(INFO) << "getting " << ValNo;
        LowLoc target_loc = locs.at(ValNo);
        LOG(INFO) << "attempting to allocate ";
        // We should use customs here the state is irrelevant
        return std::visit(
            overload{ [&State, ValNo, ValVT, LocInfo, LocVT,
                       this](const irene3::patchir::MemoryIndirectAttr &indirect) {
                         LOG(INFO) << "mem indirect";
                         // TODO(Ian): https://github.com/trailofbits/irene3/issues/337
                         State.addLoc(llvm::CCValAssign::getMem(
                             ValNo, ValVT, indirect.getOffset() - this->current_stack_offset, LocVT,
                             LocInfo));
                         return false;
                     },
                      [&State, this, ValNo, ValVT, LocVT,
                       LocInfo](const irene3::patchir::RegisterAttr &reg) {
                          auto llreg = this->getRegister(reg);
                          LOG(INFO) << "Allocating " << llreg;
                          auto res = State.AllocateReg(llreg);
                          CHECK(res);
                          State.addLoc(
                              llvm::CCValAssign::getReg(ValNo, ValVT, res, LocVT, LocInfo));
                          return false;
                      },
                      [](const irene3::patchir::MemoryAttr &) {
                          LOG(INFO) << "mem";
                          return true;
                      } },
            target_loc);
    }

    std::function< llvm::CCAssignFn > CCBuilder::BuidCCAssign(bool isReturn) {
        if (isReturn) {
            return this->summary.at_exit;
        }

        return this->summary.at_entry;
    }

    void CCBuilder::dump() const {
        std::cerr << "CCBuilder: " << std::endl;
        this->summary.dump();

        std::cerr << "/CCBuilder: " << std::endl;
    }

    ModuleCallingConventions::ModuleCallingConventions(
        mlir::ModuleOp mop, const IreneLoweringInterface &ILI, llvm::LLVMContext &context)
        : ILI(ILI)
        , type_decoder(context) {
        this->Populate(mop);
    }

    void ModuleCallingConventions::Populate(mlir::ModuleOp mop) {
        for (auto f : mop.getBodyRegion().getOps< irene3::patchir::FunctionOp >()) {
            for (auto r : f.getOps< irene3::patchir::RegionOp >()) {
                auto call   = *r.getOps< irene3::patchir::CallOp >().begin();
                auto callee = call.getCallee();

                auto summ = this->LowerVariables(call);
                builders.emplace_back(callee, CCBuilder(summ));
            }
        }
    }

    void ModuleCallingConventions::ApplyTo(llvm::Module *mod) {
        uint64_t ent = llvm::CallingConv::CUSTOM_ID_RANGE_START;
        for (auto &[x, y] : this->builders) {
            if (x) {
                auto f = mod->getFunction(*x);
                if (f) {
                    f->setCallingConv(ent);
                    LOG(INFO) << "Setting call conv " << ent;
                    f->dump();
                    y.dump();
                }
            }
            ent += 1;
        }
    }

    uint64_t ModuleCallingConventions::AddNamedCC(std::string name, CCBuilder builder) {
        this->builders.emplace_back(std::move(name), std::move(builder));
        return llvm::CallingConv::CUSTOM_ID_RANGE_START + this->builders.size() - 1;
    }

    uint64_t ModuleCallingConventions::AddCC(CCBuilder builder) {
        this->builders.emplace_back(std::nullopt, std::move(builder));
        return llvm::CallingConv::CUSTOM_ID_RANGE_START + this->builders.size() - 1;
    }

    std::unordered_map< uint64_t, CCBuilder > ModuleCallingConventions::BuildCConvMap() {
        uint64_t ent = llvm::CallingConv::CUSTOM_ID_RANGE_START;
        std::unordered_map< uint64_t, CCBuilder > res;
        for (auto it : this->builders) {
            res.emplace(ent, std::move(it.second));
            ent += 1;
        }
        return res;
    }

    void ModuleCallingConventions::dump() const {
        for (const auto &[k, v] : this->builders) {
            v.dump();
        }
    }

    CCObjSelector::CCObjSelector(std::unordered_map< uint64_t, CCBuilder > builders)
        : builders(std::move(builders)) {}

    std::function< llvm::CCAssignFn > CCObjSelector::CCAssignFnForNode(
        llvm::CallingConv::ID CC, bool Return, bool isVarArg) {
        // We use the space above the max id
        auto target = this->builders.find(CC);
        if (CC >= llvm::CallingConv::CUSTOM_ID_RANGE_START && target != this->builders.end()) {
            return target->second.BuidCCAssign(Return);
        }

        return nullptr;
    }

    void CCObjSelector::dump() const {
        for (auto &[k, v] : this->builders) {
            v.dump();
        }
    }

    static const llvm::MCPhysReg CSR_NoRegs_SaveList[] = { 0 };
    static const uint32_t CSR_NoRegs_RegMask[]         = {
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    };

    std::optional< const llvm::MCPhysReg * > CCObjSelector::getCalleeSaves(
        const llvm::MachineFunction *M) {
        if (M->getFunction().getCallingConv() >= llvm::CallingConv::CUSTOM_ID_RANGE_START) {
            return CSR_NoRegs_SaveList;
        }

        return std::nullopt;
    }

    std::optional< const uint32_t * > CCObjSelector::getCallPreservedMask(
        const llvm::MachineFunction &M, llvm::CallingConv::ID CC) {
        if (CC >= llvm::CallingConv::CUSTOM_ID_RANGE_START) {
            return CSR_NoRegs_RegMask;
        }

        return std::nullopt;
    }

    bool CCObjSelector::isTailCallEquiv(llvm::CallingConv::ID CC) {
        return CC >= llvm::CallingConv::CUSTOM_ID_RANGE_START;
    }

} // namespace irene3