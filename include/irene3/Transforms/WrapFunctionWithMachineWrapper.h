#pragma once

#include "anvill/Declarations.h"
#include "irene3/PatchIR/PatchIROps.h"
#include "irene3/Transforms/PostPass.h"
#include "irene3/Transforms/WrapBBFuncPassCodegen.h"

#include <irene3/LowLocCCBuilder.h>
#include <irene3/PhysicalLocationDecoder.h>
#include <irene3/Transforms/WrapBBFuncPass.h>
#include <llvm/CodeGen/TargetRegisterInfo.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/PassManager.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <mlir/IR/Attributes.h>
#include <mlir/IR/BuiltinOps.h>
#include <mlir/Target/LLVMIR/TypeToLLVM.h>
#include <optional>
#include <unordered_map>
#include <vector>

namespace irene3
{

    class WrapFunctionWithMachineWrapper : public PostPass< WrapFunctionWithMachineWrapper > {
      private:
        // todo fix this
        std::optional< llvm::Value * > ret_storage;
        std::optional< llvm::BasicBlock * > exit_block;

        std::optional< llvm::Value * > tmp_st;
        std::optional< llvm::StructType * > tmp_sty;

        llvm::Value *SuccessorStructValue(llvm::IRBuilder<> &, uint64_t value, bool should_return);

        auto AccessHv(llvm::IRBuilder<> &target_bldr, const LowVar &ent) -> llvm::Value *;

      public:
        static llvm::StringRef name();

        WrapFunctionWithMachineWrapper(
            llvm::LLVMContext &llcontext,
            mlir::ModuleOp mlir_module,
            const llvm::TargetRegisterInfo *reg_info,
            ModuleCallingConventions &ccmod)
            : PostPass< WrapFunctionWithMachineWrapper >(llcontext, mlir_module, reg_info, ccmod) {}

        virtual llvm::FunctionType *GetSignature(anvill::Uid, const llvm::Function *) override;

        virtual void Transform(anvill::Uid, llvm::Function &) override;

        virtual llvm::CallBase *PopulateEntryBlock(
            anvill::Uid,
            llvm::IRBuilder<> &bldr,
            llvm::Function &target,
            llvm::Function *oldfunc) override;

        void CreateExitFunction(
            patchir::CallOp cop,
            llvm::Function &target,
            const LoweredVariables &lowered,
            llvm::IRBuilder<> &exit_bldr,
            std::optional< uint64_t > addr);
    };

} // namespace irene3