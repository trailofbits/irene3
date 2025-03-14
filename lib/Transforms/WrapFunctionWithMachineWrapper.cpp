
#include <algorithm>
#include <anvill/ABI.h>
#include <anvill/Declarations.h>
#include <glog/logging.h>
#include <irene3/IreneLoweringInterface.h>
#include <irene3/LowLocCCBuilder.h>
#include <irene3/PatchIR/PatchIRAttrs.h>
#include <irene3/PatchIR/PatchIROps.h>
#include <irene3/PatchIR/PatchIRTypes.h>
#include <irene3/PhysicalLocationDecoder.h>
#include <irene3/Transforms/PostPass.h>
#include <irene3/Transforms/WrapFunctionWithMachineWrapper.h>
#include <irene3/Util.h>
#include <iterator>
#include <llvm/ADT/APFloat.h>
#include <llvm/CodeGen/MachineValueType.h>
#include <llvm/CodeGen/TargetRegisterInfo.h>
#include <llvm/IR/Attributes.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constant.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/Value.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/raw_ostream.h>
#include <mlir/Dialect/LLVMIR/LLVMDialect.h>
#include <mlir/IR/BuiltinOps.h>
#include <mlir/Support/LLVM.h>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace irene3
{

    llvm::FunctionType *SignatureForWrapper(
        llvm::LLVMContext &context, const LoweredVariables &copinfo) {
        std::vector< llvm::Type * > args;
        std::vector< llvm::Type * > retys;

        std::transform(
            copinfo.at_entry.begin(), copinfo.at_entry.end(), std::back_inserter(args),
            [&context](const LowVar &lv) -> llvm::Type * {
                return ConvertMVT(context, lv.assignment.type);
            });

        llvm::Type *rety = nullptr;
        return llvm::FunctionType::get(rety, args, false);
    }

    llvm::Type *SuccessorStruct(const llvm::Module *mod) {
        auto addr_ty = AddressType(mod);
        return llvm::StructType::get(
            mod->getContext(), { addr_ty, llvm::IntegerType::get(mod->getContext(), 1) });
    }

    llvm::FunctionType *WrapFunctionWithMachineWrapper::GetSignature(
        anvill::Uid uid, const llvm::Function *f) {
        patchir::CallOp cop = this->uid_to_caller.at(uid);
        auto lowered        = this->LowerVariables(cop);

        std::vector< llvm::Type * > entry_types;

        for (const auto &comps : lowered.at_entry.Components()) {
            for (const auto &comp : comps) {
                entry_types.push_back(ConvertMVT(f->getContext(), comp->GetMVT()));
            }
        }

        auto res
            = llvm::FunctionType::get(llvm::Type::getVoidTy(f->getContext()), entry_types, false);
        res->dump();
        return res;
    }

    void WrapFunctionWithMachineWrapper::Transform(anvill::Uid uid, llvm::Function &F) {
        std::vector< llvm::CallBase * > calls_to_goto;
        patchir::CallOp cop = this->uid_to_caller.at(uid);
        auto lowered        = this->LowerVariables(cop);
        for (auto &insn : llvm::instructions(F)) {
            if (llvm::CallBase *cb = llvm::dyn_cast< llvm::CallBase >(&insn)) {
                if (cb->getCalledFunction()
                    && cb->getCalledFunction()->getName() == anvill::kAnvillGoto) {
                    calls_to_goto.push_back(cb);
                }
            }
        }

        for (auto cb : calls_to_goto) {
            llvm::IRBuilder<> bldr(cb);
            // auto addr      = AddressType(F.getParent());
            CHECK(llvm::isa< llvm::Constant >(cb->getArgOperand(0)));
            auto target_pc = llvm::ConstantExpr::getIntToPtr(
                llvm::cast< llvm::Constant >(cb->getArgOperand(0)),
                llvm::PointerType::get(cb->getContext(), 0));

            auto old_block = cb->getParent();
            // split off everything after the
            old_block->erase(cb->getIterator(), old_block->end());
            bldr.SetInsertPoint(old_block);
            this->CreateExitFunction(F, lowered, bldr, target_pc);
        }
    }

    llvm::Value *WrapFunctionWithMachineWrapper::SuccessorStructValue(
        llvm::IRBuilder<> &bldr, uint64_t value, bool should_return) {
        auto mod     = bldr.GetInsertBlock()->getModule();
        auto strucft = SuccessorStruct(mod);
        auto u       = llvm::UndefValue::get(strucft);
        auto with_addr
            = bldr.CreateInsertValue(u, llvm::ConstantInt::get(AddressType(mod), value), { 0 });
        return bldr.CreateInsertValue(
            with_addr, llvm::ConstantInt::getBool(strucft->getContext(), should_return), { 1 });
    }

    namespace
    {

    } // namespace

    llvm::Value *WrapFunctionWithMachineWrapper::AccessHv(
        llvm::IRBuilder<> &target_bldr, size_t high_index) {
        auto i32 = llvm::IntegerType::getInt32Ty(target_bldr.getContext());
        return target_bldr.CreateGEP(
            *this->tmp_sty, *this->tmp_st,
            { llvm::ConstantInt::getNullValue(i32), llvm::ConstantInt::get(i32, high_index) });
    }

    void WrapFunctionWithMachineWrapper::CreateExitFunction(
        llvm::Function &target,
        const RegionSummary &lowered,
        llvm::IRBuilder<> &exit_bldr,
        llvm::Value *addr) {
        CHECK(addr->getType()->isPointerTy());
        std::vector< llvm::Value * > exiter_args;

        size_t high_index = 0;
        for (auto ent : lowered.at_exit.Components()) {
            for (const auto &comp : ent) {
                exiter_args.push_back(comp->Load(exit_bldr, AccessHv(exit_bldr, high_index)));
            }
            high_index++;
        }

        // to hit an exit we declare an exit function with a custom calling convention
        // target.setDoesNotReturn();

        // exiters have the semantics of entry at exit
        auto cc_id = this->collected_ccs.AddCC(CCBuilder({ lowered.at_exit, lowered.at_exit }));

        auto call = exit_bldr.CreateCall(
            CreateExitingFunctionTy(target.getContext(), lowered), addr, exiter_args);

        SetRelativeCallMetada(call);
        call->setCallingConv(cc_id);
        // call->setDoesNotReturn();
        call->setTailCall(true);

        exit_bldr.CreateRet(nullptr);
    }

    llvm::CallBase *WrapFunctionWithMachineWrapper::PopulateEntryBlock(
        anvill::Uid uid, llvm::IRBuilder<> &bldr, llvm::Function &target, llvm::Function *oldfunc) {
        patchir::CallOp cop = this->uid_to_caller.at(uid);

        target.addFnAttr(llvm::Attribute::NoReturn);
        target.addFnAttr(llvm::Attribute::NoUnwind);
        auto lowered = this->LowerVariables(cop);

        auto &context = target.getContext();
        auto parms    = oldfunc->getFunctionType()->params();

        std::vector< llvm::Type * > high_types;
        for (auto op : cop->getOperands()) {
            auto elty = mlir::cast< patchir::LowValuePointerType >(op.getType()).getElement();
            high_types.push_back(this->type_decoder.translateType(elty));
        }

        this->tmp_sty     = llvm::StructType::get(target.getContext(), high_types);
        this->tmp_st      = bldr.CreateAlloca(*this->tmp_sty);
        auto succ_ty      = SuccessorStruct(target.getParent());
        auto succ_storage = bldr.CreateAlloca(succ_ty);
        this->ret_storage = succ_storage;

        auto i32 = llvm::IntegerType::getInt32Ty(target.getContext());

        std::vector< llvm::Value * > args;
        for (size_t i = 0; i < parms.size(); i++) {
            args.push_back(bldr.CreateGEP(
                *tmp_sty, *tmp_st,
                { llvm::ConstantInt::getNullValue(i32), llvm::ConstantInt::get(i32, i) }));
        }

        size_t ind      = 0;
        size_t high_ind = 0;
        for (auto ent_comp : lowered.at_entry.Components()) {
            for (auto comp : ent_comp) {
                comp->Store(bldr, target.getArg(ind), AccessHv(bldr, high_ind));
                ind += 1;
            }

            high_ind += 1;
        }

        auto cb         = bldr.CreateCall(oldfunc, args);
        auto exit_block = llvm::BasicBlock::Create(context, "", &target);
        bldr.CreateBr(exit_block);
        this->exit_block = exit_block;

        llvm::IRBuilder<> exit_bldr(exit_block);
        // TODO(Ian): support returning out of a block...
        CreateExitFunction(
            target, lowered, exit_bldr,
            llvm::UndefValue::get(llvm::PointerType::get(target.getContext(), 0)));

        return cb;
    }

    llvm::StringRef WrapFunctionWithMachineWrapper::name(void) {
        return "WrapFunctionWithMachineWrapper";
    }

} // namespace irene3
