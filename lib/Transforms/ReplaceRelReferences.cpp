#include "anvill/Declarations.h"
#include "irene3/LowLocCCBuilder.h"
#include "irene3/PatchIR/PatchIRAttrs.h"
#include "irene3/PatchIR/PatchIROps.h"
#include "irene3/Util.h"

#include <algorithm>
#include <irene3/Transforms/ReplaceRelReferences.h>
#include <llvm/CodeGen/MachineValueType.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Value.h>
#include <llvm/Support/Casting.h>
#include <llvm/TargetParser/Triple.h>
#include <mlir/IR/BuiltinAttributes.h>
#include <optional>
#include <unordered_map>
#include <variant>
#include <vector>

namespace irene3
{
    llvm::StringRef ReplaceRelReferences::name() { return "ReplaceRelReferences"; }

    namespace
    {
        llvm::IntegerType *AddressType(const llvm::Module *mod) {
            return llvm::IntegerType::get(
                mod->getContext(), mod->getDataLayout().getPointerSizeInBits());
        }

    } // namespace

    llvm::FunctionType *ReplaceRelReferences::GetSignature(
        anvill::Uid, const llvm::Function *oldf) {
        for (auto gb : mlir_module.getOps< patchir::Global >()) {
            auto gv = oldf->getParent()->getGlobalVariable(gb.getTargetSymName());
            if (gv) {
                auto addmem = gb.getMem();
                this->addressing_table.insert({
                    gv, FlatAddr{addmem.getAddr(), addmem.getDisp(), addmem.getIsExternal()}
                });
            }
        }

        for (auto gb : mlir_module.getOps< patchir::FunctionOp >()) {
            auto f = oldf->getParent()->getFunction(gb.getNameAttr().str());
            if (f) {
                this->addressing_table.insert({
                    f,
                    FlatAddr{gb.getAddress(), gb.getDispAttr().getSInt(), gb.getIsExternal()}
                });
            }
        }

        auto oldsig = oldf->getFunctionType();
        std::vector< llvm::Type * > newargs(oldsig->params());
        newargs.push_back(AddressType(oldf->getParent()));
        return llvm::FunctionType::get(oldsig->getReturnType(), newargs, false);
    }

    void ReplaceRelReferences::Transform(anvill::Uid, llvm::Function &f) {
        // find used globals and replace with a base relative address
        std::vector< llvm::Use * > to_replace;
        std::vector< FlatAddr > globals;
        for (auto &gv : f.getParent()->global_objects()) {
            for (auto &use : gv.uses()) {
                if (auto *insn = llvm::dyn_cast< llvm::Instruction >(use.getUser())) {
                    if (insn->getFunction() == &f
                        && this->addressing_table.find(&gv) != this->addressing_table.end()) {
                        to_replace.push_back(&use);
                        globals.push_back(this->addressing_table.find(&gv)->second);
                    }
                }
            }
        }

        // replace globals
        size_t ind = 0;
        for (auto to_repr : to_replace) {
            auto gb = globals[ind];
            llvm::IRBuilder<> builder(llvm::cast< llvm::Instruction >(to_repr->getUser()));
            auto image_base = (f.arg_end() - 1);
            auto addr_ty    = AddressType(f.getParent());
            auto naddr      = builder.CreateAdd(
                image_base, llvm::ConstantInt::get(addr_ty, gb.addr - this->image_base));
            auto orig_ty  = gb.is_external ? llvm::PointerType::get(f.getContext(), 0)
                                           : to_repr->get()->getType();
            auto orig_ptr = builder.CreateIntToPtr(naddr, orig_ty);

            auto target_ptr = orig_ptr;
            if (gb.is_external) {
                target_ptr = builder.CreateIntToPtr(
                    builder.CreateAdd(
                        builder.CreateLoad(addr_ty, target_ptr),
                        llvm::ConstantInt::get(addr_ty, gb.disp)),
                    to_repr->get()->getType());
            }

            to_repr->set(target_ptr);
            ind++;
        }

        // replace function calls that we attached metadata to  (basic block calls)
        std::vector< llvm::CallBase * > to_repl_funcs;
        for (auto &insn : llvm::instructions(f)) {
            if (auto *cb = llvm::dyn_cast< llvm::CallBase >(&insn)) {
                if (cb->getCalledFunction() && GetPCMetadata(cb->getCalledFunction())) {
                    to_repl_funcs.push_back(cb);
                }
            }
        }

        for (auto cb : to_repl_funcs) {
            uint64_t pc = *GetPCMetadata(cb->getCalledFunction());
            auto old_ty = cb->getFunctionType();
            llvm::IRBuilder<> builder(cb);
            auto naddr = builder.CreateAdd(
                (f.arg_end() - 1),
                llvm::ConstantInt::get(AddressType(f.getParent()), pc - this->image_base));
            auto casted = builder.CreateIntToPtr(naddr, cb->getCalledFunction()->getType());

            cb->setCalledOperand(casted);

            CHECK(old_ty == cb->getFunctionType());
        }
    }

    std::optional< std::string > ReplaceRelReferences::GetImageBaseReg() const {
        if (this->image_base_storage) {
            return this->image_base_storage->getReg().str();
        }

        return std::nullopt;
    }

    namespace
    {
        const std::unordered_map< std::string, std::vector< std::string > >
            allocateableRegClassesForTarget = {
                {"arm", { "tGPR" }}
        };
    }

    irene3::patchir::RegisterAttr ReplaceRelReferences::CreateAddrTypedReg(
        llvm::Module *mod, const std::vector< LowLoc > &live_entries) {
        auto addrty  = AddressType(mod);
        auto addrtmv = llvm::MVT::getIntegerVT(addrty->getBitWidth());
        std::vector< llvm::MCPhysReg > regs;

        std::vector< irene3::patchir::RegisterAttr > free_reglist;

        for (const auto &loc : live_entries) {
            if (std::holds_alternative< irene3::patchir::RegisterAttr >(loc)) {
                auto curr_r = std::get< irene3::patchir::RegisterAttr >(loc);
                auto nm     = curr_r.getReg().str();
                std::transform(nm.begin(), nm.end(), nm.begin(), ::toupper);
                auto maybe_reg = tt_translator.getRegTable().lookup(nm);
                if (maybe_reg) {
                    regs.push_back(*maybe_reg);
                }
            }
        }
        llvm::Triple trip(mod->getTargetTriple());

        for (auto rc : allocateableRegClassesForTarget.at(trip.getArchName().str())) {
            if (this->name_to_register_class.find(rc) != this->name_to_register_class.end()) {
                auto r_class = this->name_to_register_class.find(rc)->second;
                if (this->reg_info->isTypeLegalForClass(*r_class, addrtmv)) {
                    for (auto r : r_class->getRegisters()) {
                        bool overlaps = false;
                        // TODO(Ian): do better
                        for (auto allocated : regs) {
                            overlaps |= this->reg_info->regsOverlap(r, allocated);
                        }

                        if (!overlaps) {
                            regs.push_back(r);
                            free_reglist.push_back(irene3::patchir::RegisterAttr::get(
                                this->mlir_module->getContext(),
                                mlir::StringAttr::get(
                                    this->mlir_module->getContext(), this->reg_info->getName(r)),
                                addrty->getBitWidth()));
                        }
                    }
                }
            }
        }

        LOG_IF(FATAL, free_reglist.empty()) << "No available register for the address";

        auto res = free_reglist.back();
        free_reglist.pop_back();
        this->free_reg_list = free_reglist;
        return res;
    }

    llvm::CallBase *ReplaceRelReferences::PopulateEntryBlock(
        anvill::Uid uid, llvm::IRBuilder<> &bldr, llvm::Function &target, llvm::Function *oldfunc) {
        patchir::CallOp cop = this->uid_to_caller.at(uid);

        CallOpInfo info(cop);

        auto norm_entry          = info.at_entry;
        this->image_base_storage = CreateAddrTypedReg(target.getParent(), info.at_entry);
        norm_entry.push_back(*this->image_base_storage);
        auto ccid = this->collected_ccs.AddCC(
            oldfunc->getName().str(),
            CCBuilder(norm_entry, info.at_exit, info.entry_stack_offset, info.exit_stack_offset));

        target.setCallingConv(ccid);

        // target.addFnAttr(llvm::Attribute::NoReturn);
        target.addFnAttr(llvm::Attribute::NoUnwind);
        std::vector< llvm::Value * > args;
        for (size_t ind = 0; ind < oldfunc->arg_size(); ind++) {
            args.push_back(target.getArg(ind));
        }

        auto call = bldr.CreateCall(oldfunc, args);
        // target.setDoesNotReturn();
        //  call->setDoesNotReturn();
        bldr.CreateRet(nullptr);

        return call;
    }
} // namespace irene3