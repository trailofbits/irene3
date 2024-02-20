#include "irene3/Transforms/RestoreStackRelations.h"

#include "irene3/IreneLoweringInterface.h"

#include <algorithm>
#include <anvill/Declarations.h>
#include <irene3/LowLocCCBuilder.h>
#include <irene3/PatchIR/PatchIRAttrs.h>
#include <irene3/PatchIR/PatchIROps.h>
#include <irene3/Transforms/ReplaceRelReferences.h>
#include <irene3/Util.h>
#include <llvm/CodeGen/MachineValueType.h>
#include <llvm/IR/CallingConv.h>
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
#include <llvm/IR/PassManager.h>
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

    llvm::StringRef RestoreStackRelations::name() { return "RestoreStackRelations"; }

    llvm::FunctionType *RestoreStackRelations::GetSignature(
        anvill::Uid uid, const llvm::Function *f) {
        auto cop = this->uid_to_caller.at(uid);
        RegionSummary summ
            = this->collected_ccs.BuildCConvMap().at(f->getCallingConv()).GetRegionSummary();
        auto reg             = cop->getParentOfType< patchir::RegionOp >();
        auto soffs           = reg.getEntryStackOffsets();
        auto high_index_last = summ.at_entry.Components().size();
        auto low_args_last   = f->arg_size();
        for (auto soff : soffs.getAsRange< patchir::StackOffsetAttr >()) {
            summ.at_entry.addComponent(
                this->LowerVariable(soff.getReg(), high_index_last, AddressType(f->getParent())));
            this->reg_to_stack_offset_and_index.insert({
                soff.getReg().getReg().str(), {soff.getOffset(), low_args_last}
            });

            high_index_last += 1;
            low_args_last += 1;
        }

        this->summ_sig = summ;

        auto fty = CreateRegionSigFuncTy(f->getContext(), summ.at_entry);
        return fty;
    }

    void RestoreStackRelations::Transform(anvill::Uid basic_block_addr, llvm::Function &F) {
        auto cop = this->uid_to_caller.at(basic_block_addr);

        // find terminal calls and extend them.
        auto st = llvm::PreservedAnalyses::all();
        std::vector< llvm::CallInst * > to_rewrite;
        for (auto &insn : llvm::instructions(F)) {
            if (auto cb = llvm::dyn_cast< llvm::CallInst >(&insn)) {
                if (cb->getCallingConv() >= llvm::CallingConv::CUSTOM_ID_RANGE_START) {
                    to_rewrite.push_back(cb);
                    st.intersect(llvm::PreservedAnalyses::none());
                }
            }
        }

        for (auto cb : to_rewrite) {
            RewriteCall(*cb, cop);
        }
    }

    llvm::CallBase *RestoreStackRelations::PopulateEntryBlock(
        anvill::Uid uid, llvm::IRBuilder<> &bldr, llvm::Function &target, llvm::Function *oldfunc) {
        patchir::CallOp cop = this->uid_to_caller.at(uid);

        CallOpInfo info(cop);

        auto ccid
            = this->collected_ccs.AddNamedCC(oldfunc->getName().str(), CCBuilder(*this->summ_sig));

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

    OffAndIndex RestoreStackRelations::GetReprStackOffset(
        patchir::RegisterAttr rattr, int64_t target_off) {
        auto maybe_exact = this->reg_to_stack_offset_and_index.find(rattr.getReg().str());
        if (maybe_exact != this->reg_to_stack_offset_and_index.end()) {
            if (maybe_exact->second.offset == target_off) {
                return maybe_exact->second;
            }
        }
        auto sp = this->ILI.StackRegister();
        if (sp) {
            auto nm = this->reg_info->getName(*this->ILI.StackRegister());
            if (this->reg_to_stack_offset_and_index.contains(nm)) {
                return this->reg_to_stack_offset_and_index.at(nm);
            }
        }

        if (this->reg_to_stack_offset_and_index.begin()
            != this->reg_to_stack_offset_and_index.end()) {
            return this->reg_to_stack_offset_and_index.begin()->second;
        }

        LOG(FATAL) << "No viable stack base for function";
    }

    void RestoreStackRelations::RewriteCall(llvm::CallInst &cb, patchir::CallOp cop) {
        std::vector< llvm::Value * > args;
        for (auto &prev : cb.args()) {
            args.push_back(prev.get());
        }

        RegionSignature exit_sig = this->summ_sig->at_exit;

        llvm::IRBuilder<> bldr(&cb);

        auto reg   = cop->getParentOfType< patchir::RegionOp >();
        auto soffs = reg.getExitStackOffsets();

        // add vars to calling conv
        size_t high_ind = exit_sig.Components().size();

        for (auto soff : soffs.getAsRange< patchir::StackOffsetAttr >()) {
            // find a representative for this stack offset (either prefer an equiv or pipe
            // everything to the sp representative)
            auto target = this->GetReprStackOffset(soff.getReg(), soff.getOffset());

            // add vars to calling conv
            exit_sig.addComponent(
                this->LowerVariable(soff.getReg(), high_ind, AddressType(cb.getModule())));

            // Create a stack value:

            auto addr_ty = AddressType(cb.getModule());
            auto sp_val
                = bldr.CreateZExtOrTrunc(cb.getFunction()->getArg(target.arg_index), addr_ty);
            auto diff = soff.getOffset() - target.offset;
            if (diff != 0) {
                sp_val = bldr.CreateAdd(sp_val, llvm::ConstantInt::get(addr_ty, diff, true));
            }
            args.push_back(sp_val);
            high_ind += 1;
        }

        auto fty  = CreateRegionSigFuncTy(cb.getContext(), exit_sig);
        auto call = bldr.CreateCall(fty, cb.getCalledOperand(), args);
        auto nid  = this->collected_ccs.AddCC(CCBuilder({ exit_sig, exit_sig }));
        call->setCallingConv(nid);
        call->setTailCall(true);
        cb.eraseFromParent();
    }

    /*
            auto cop    = this->uid_to_caller.at(uid);
        auto reg    = cop->getParentOfType< patchir::RegionOp >();*/

} // namespace irene3
