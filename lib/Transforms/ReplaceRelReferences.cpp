#include <algorithm>
#include <anvill/Declarations.h>
#include <irene3/LowLocCCBuilder.h>
#include <irene3/PatchIR/PatchIRAttrs.h>
#include <irene3/PatchIR/PatchIROps.h>
#include <irene3/Transforms/ReplaceRelReferences.h>
#include <irene3/Util.h>
#include <llvm/CodeGen/MachineValueType.h>
#include <llvm/IR/Constant.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/ReplaceConstant.h>
#include <llvm/IR/Use.h>
#include <llvm/IR/Value.h>
#include <llvm/Support/Casting.h>
#include <llvm/TargetParser/Triple.h>
#include <mlir/IR/BuiltinAttributes.h>
#include <optional>
#include <remill/BC/Util.h>
#include <unordered_map>
#include <variant>
#include <vector>

namespace irene3
{
    llvm::StringRef ReplaceRelReferences::name() { return "ReplaceRelReferences"; }

    namespace
    {

    } // namespace

    llvm::FunctionType *ReplaceRelReferences::GetSignature(
        anvill::Uid, const llvm::Function *oldf) {
        for (auto gb : mlir_module.getOps< patchir::Global >()) {
            auto gv = oldf->getParent()->getGlobalVariable(gb.getTargetSymName());
            if (gv) {
                auto addmem = gb.getMem();
                LOG(INFO) << "adding table entry for gv: " << gb.getTargetSymName().str();
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
            if (this->addressing_table.find(&gv) != this->addressing_table.end()) {
                llvm::convertUsersOfConstantsToInstructions({ &gv });
            }
        }

        for (auto &gv : f.getParent()->global_objects()) {
            for (auto &use : gv.uses()) {
                if (auto insn = llvm::dyn_cast< llvm::Instruction >(use.getUser())) {
                    if (insn->getFunction() == &f
                        && this->addressing_table.find(&gv) != this->addressing_table.end()) {
                        to_replace.push_back(&use);
                        globals.push_back(this->addressing_table.find(&gv)->second);
                    }
                }
            }
        }

        auto repr_intrinsic = llvm::Intrinsic::getDeclaration(
            f.getParent(), llvm::Intrinsic::addrrepr,
            { llvm::PointerType::get(f.getContext(), 0),
              llvm::PointerType::get(f.getContext(), 0) });

        // replace globals
        size_t ind = 0;
        for (auto to_repr : to_replace) {
            LOG(INFO) << "replacing " << remill::LLVMThingToString(to_repr->get());
            auto gb = globals[ind];
            llvm::IRBuilder<> builder(llvm::cast< llvm::Instruction >(to_repr->getUser()));
            auto image_base   = (f.arg_end() - 1);
            auto addr_ty      = AddressType(f.getParent());
            auto orig_ty      = gb.is_external ? llvm::PointerType::get(f.getContext(), 0)
                                               : to_repr->get()->getType();
            llvm::Value *addr = llvm::ConstantExpr::getIntToPtr(
                llvm::ConstantInt::get(addr_ty, gb.addr - this->image_base), orig_ty);
            if (!llvm::isa< llvm::GlobalVariable >(to_repr->get())) {
                addr = builder.CreateCall(
                    repr_intrinsic, { addr, llvm::ConstantInt::get(
                                                llvm::IntegerType::get(f.getContext(), 32), 0) });
            }

            auto naddr = builder.CreateAdd(image_base, builder.CreatePtrToInt(addr, addr_ty));

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
                if (IsRelativeCall(cb)) {
                    to_repl_funcs.push_back(cb);
                }
            }
        }

        for (auto cb : to_repl_funcs) {
            if (IsRelativeCall(cb)) {
                auto old_ty = cb->getFunctionType();
                llvm::IRBuilder<> builder(cb);
                auto addr_ty = AddressType(f.getParent());

                auto rebased_addr = llvm::ConstantExpr::getSub(
                    llvm::ConstantExpr::getPtrToInt(
                        llvm::cast< llvm::Constant >(cb->getCalledOperand()), addr_ty),
                    llvm::ConstantInt::get(addr_ty, this->image_base));

                auto marked_rebased = builder.CreateCall(
                    repr_intrinsic,
                    { llvm::ConstantExpr::getIntToPtr(
                          rebased_addr, cb->getCalledOperand()->getType()),
                      llvm::ConstantInt::get(llvm::IntegerType::get(f.getContext(), 32), 1) });

                auto naddr = builder.CreateAdd(
                    (f.arg_end() - 1), builder.CreatePtrToInt(marked_rebased, addr_ty));
                auto casted = builder.CreateIntToPtr(naddr, cb->getCalledOperand()->getType());

                cb->setCalledOperand(casted);

                CHECK(old_ty == cb->getFunctionType());
            }
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
                {  "arm", { "tGPR" }},
                {"thumb", { "tGPR" }}
        };
    }

    irene3::patchir::RegisterAttr ReplaceRelReferences::CreateAddrTypedReg(
        llvm::Module *mod,
        const std::vector< LowLoc > &live_entries,
        std::vector< patchir::RegisterAttr > additionalregs) {
        auto addrty = AddressType(mod);

        std::vector< llvm::MCPhysReg > regs;

        std::vector< irene3::patchir::RegisterAttr > free_reglist;

        for (const auto &loc : live_entries) {
            if (std::holds_alternative< irene3::patchir::RegisterAttr >(loc)) {
                additionalregs.push_back(std::get< irene3::patchir::RegisterAttr >(loc));
            }
        }

        for (auto curr_r : additionalregs) {
            auto nm = curr_r.getReg().str();
            std::transform(nm.begin(), nm.end(), nm.begin(), ::toupper);
            auto maybe_reg = rtable.lookup(nm);
            if (maybe_reg) {
                regs.push_back(*maybe_reg);
            }
        }

        for (auto r : this->ILI.PointerRegs()) {
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
        auto summ = this->LowerVariables(cop);

        std::vector< irene3::patchir::RegisterAttr > additionalregs;
        for (auto reg : cop->getParentOfType< patchir::RegionOp >()
                            .getEntryStackOffsets()
                            .getAsRange< irene3::patchir::StackOffsetAttr >()) {
            additionalregs.push_back(reg.getReg());
        }

        auto all_regs = info.at_entry;
        all_regs.insert(all_regs.end(), info.at_exit.begin(), info.at_exit.end());

        this->image_base_storage = CreateAddrTypedReg(target.getParent(), all_regs, additionalregs);
        summ.at_entry.addComponent(this->LowerVariable(
            *this->image_base_storage, summ.at_entry.Components().size(),
            AddressType(target.getParent())));

        auto ccid = this->collected_ccs.AddNamedCC(oldfunc->getName().str(), CCBuilder(summ));

        LOG(INFO) << "Post collected ccid " << ccid << " for " << oldfunc->getName().str();

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