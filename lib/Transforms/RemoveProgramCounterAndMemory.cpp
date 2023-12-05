
#include "anvill/ABI.h"
#include "anvill/Declarations.h"

#include <algorithm>
#include <anvill/Utils.h>
#include <cstddef>
#include <irene3/Transforms/RemoveProgramCounterAndMemory.h>
#include <irene3/Util.h>
#include <iterator>
#include <llvm/ADT/APInt.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/IR/Attributes.h>
#include <llvm/IR/Constant.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Type.h>
#include <llvm/Support/Casting.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Util.h>
#include <vector>
namespace irene3
{

    llvm::StringRef RemoveProgramCounterAndMemory::name() {
        return "RemoveProgramCounterAndMemory";
    }

    llvm::FunctionType *RemoveProgramCounterAndMemory::GetSignature(
        const BBInfo &bbinfo, const llvm::Function *f) {
        CHECK(f->getFunctionType()->getNumParams() == bbinfo.fdecl.in_scope_variables.size() + 3);
        std::vector< llvm::Type * > args(
            bbinfo.context.LiveParamsAtEntryAndExit().size(),
            llvm::PointerType::get(f->getContext(), 0));

        return llvm::FunctionType::get(f->getReturnType(), args, false);
    }

    void RemoveProgramCounterAndMemory::Transform(const BBInfo &info, llvm::Function &f) {
        auto mod       = f.getParent();
        auto ptrbtsize = mod->getDataLayout().getPointerSizeInBits();
        auto addrty    = llvm::IntegerType::get(mod->getContext(), ptrbtsize);

        std::vector< llvm::CallBase * > target;
        for (auto &insn : llvm::instructions(&f)) {
            if (llvm::CallBase *cb = llvm::dyn_cast< llvm::CallBase >(&insn)) {
                auto callee = cb->getCalledFunction();
                if (callee && anvill::GetBasicBlockUid(callee)) {
                    target.push_back(cb);
                }
            }
        }

        for (auto cb : target) {
            auto callee = cb->getCalledFunction();
            auto uid    = *anvill::GetBasicBlockUid(callee);
            auto addr   = info.fdecl.cfg.at(uid).addr;
            llvm::IRBuilder<> bldr(cb);
            auto tocall = GetOrCreateGotoInstrinsic(mod, addrty);
            auto cc     = bldr.CreateCall(tocall, { llvm::ConstantInt::get(addrty, addr) });
            // so we replace with a noreturn intrinsic to avoid typing
            cc->setDoesNotReturn();
            cb->replaceAllUsesWith(llvm::UndefValue::get(f.getFunctionType()->getReturnType()));
            cb->eraseFromParent();
        }
    }

    llvm::CallBase *RemoveProgramCounterAndMemory::PopulateEntryBlock(
        const BBInfo &info,
        llvm::IRBuilder<> &bldr,
        llvm::Function &target,
        llvm::Function *oldfunc) {
        std::vector< llvm::Value * > args;

        auto null = llvm::Constant::getNullValue(llvm::PointerType::get(oldfunc->getContext(), 0));
        llvm::Type *pc_ty = oldfunc->getArg(1)->getType();
        args.push_back(null);
        args.push_back(llvm::ConstantInt::get(pc_ty, info.cb.addr));
        args.push_back(null);

        // for pointers that are not live we just assign undef
        std::fill_n(
            std::back_inserter(args), info.fdecl.in_scope_variables.size(),
            llvm::UndefValue::get(llvm::PointerType::get(oldfunc->getContext(), 0)));
        size_t live_value = 0;
        for (auto live : info.context.LiveParamsAtEntryAndExit()) {
            args[3 + info.context.GetParamIndex(live.param)] = target.getArg(live_value++);
        }

        auto cc = bldr.CreateCall(oldfunc, args);
        if (cc->getType()->isVoidTy()) {
            bldr.CreateRetVoid();
        } else {
            bldr.CreateRet(cc);
        }
        return cc;
    }
} // namespace irene3