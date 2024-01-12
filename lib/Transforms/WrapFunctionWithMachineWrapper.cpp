
#include <algorithm>
#include <anvill/ABI.h>
#include <anvill/Declarations.h>
#include <glog/logging.h>
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
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
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

    llvm::Type *ConvertMVT(llvm::LLVMContext &context, llvm::MVT svt) {
        if (svt.isInteger()) {
            return llvm::IntegerType::get(context, svt.getFixedSizeInBits());
        } else if (svt.isFloatingPoint()) {
            switch (svt.getFixedSizeInBits()) {
                case 16: return llvm::Type::getHalfTy(context);
                case 32: return llvm::Type::getFloatTy(context);
                case 64: return llvm::Type::getDoubleTy(context);
                case 128: return llvm::Type::getFP128Ty(context);
                default: {
                    LOG(FATAL) << "Unknown float " << svt.getFixedSizeInBits();
                    return nullptr;
                };
            }
        }

        std::string s;
        llvm::raw_string_ostream os(s);
        svt.print(os);
        LOG(FATAL) << "unable to convert mvt: " << s;
    }

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

    namespace
    {
        llvm::Type *AddressType(const llvm::Module *mod) {
            return llvm::IntegerType::get(
                mod->getContext(), mod->getDataLayout().getPointerSizeInBits());
        }

    } // namespace

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

        std::transform(
            lowered.at_entry.begin(), lowered.at_entry.end(), std::back_inserter(entry_types),
            [f](const LowVar &lv) -> llvm::Type * {
                return ConvertMVT(f->getContext(), lv.assignment.type);
            });

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
            auto target_pc = bldr.CreateIntToPtr(
                cb->getArgOperand(0), llvm::PointerType::get(cb->getContext(), 0));
            auto old_block = cb->getParent();
            // split off everything after the
            old_block->erase(cb->getIterator(), old_block->end());
            bldr.SetInsertPoint(old_block);
            this->CreateExitFunction(cop, F, lowered, bldr, target_pc);
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
        llvm::FunctionType *CreateExitingFunctionTy(
            llvm::Function &target, const LoweredVariables &lv) {
            std::vector< llvm::Type * > args;

            for (const auto &vs : lv.at_exit) {
                auto ty = ConvertMVT(target.getContext(), vs.assignment.type);
                args.push_back(ty);
            }

            return llvm::FunctionType::get(llvm::Type::getVoidTy(target.getContext()), args, false);
        }

    } // namespace

    llvm::Value *WrapFunctionWithMachineWrapper::AccessHv(
        llvm::IRBuilder<> &target_bldr, const LowVar &ent) {
        auto i32 = llvm::IntegerType::getInt32Ty(target_bldr.getContext());
        return target_bldr.CreateGEP(
            *this->tmp_sty, *this->tmp_st,
            { llvm::ConstantInt::getNullValue(i32), llvm::ConstantInt::get(i32, ent.high_index) });
    }

    void WrapFunctionWithMachineWrapper::CreateExitFunction(
        patchir::CallOp cop,
        llvm::Function &target,
        const LoweredVariables &lowered,
        llvm::IRBuilder<> &exit_bldr,
        llvm::Value *addr) {
        CHECK(addr->getType()->isPointerTy());
        std::vector< llvm::Value * > exiter_args;

        for (auto ent : lowered.at_exit) {
            auto value = exit_bldr.CreateLoad(
                ConvertMVT(target.getContext(), ent.assignment.type), AccessHv(exit_bldr, ent));
            exiter_args.push_back(value);
        }

        // to hit an exit we declare an exit function with a custom calling convention
        // target.setDoesNotReturn();

        CallOpInfo copinfo(cop);
        auto cc_vals = copinfo.at_exit;

        auto cc_id = this->collected_ccs.AddCC(CCBuilder(
            copinfo.at_exit, copinfo.at_exit, copinfo.exit_stack_offset,
            copinfo.exit_stack_offset));

        auto call
            = exit_bldr.CreateCall(CreateExitingFunctionTy(target, lowered), addr, exiter_args);

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

        size_t ind = 0;
        for (auto ent : lowered.at_entry) {
            bldr.CreateStore(target.getArg(ind), AccessHv(bldr, ent));
            ind += 1;
        }

        auto cb         = bldr.CreateCall(oldfunc, args);
        auto exit_block = llvm::BasicBlock::Create(context, "", &target);
        bldr.CreateBr(exit_block);
        this->exit_block = exit_block;

        llvm::IRBuilder<> exit_bldr(exit_block);
        // TODO(Ian): support returning out of a block...
        CreateExitFunction(
            cop, target, lowered, exit_bldr,
            llvm::UndefValue::get(llvm::PointerType::get(target.getContext(), 0)));

        return cb;
    }

    llvm::StringRef WrapFunctionWithMachineWrapper::name(void) {
        return "WrapFunctionWithMachineWrapper";
    }

} // namespace irene3
