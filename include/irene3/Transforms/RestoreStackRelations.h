#pragma once

#include "irene3/PatchIR/PatchIRAttrs.h"
#include "irene3/Transforms/ModuleBBPass.h"
#include "irene3/Transforms/PostWrappingPass.h"

#include <anvill/Declarations.h>
#include <cstdint>
#include <irene3/IreneLoweringInterface.h>
#include <irene3/LowLocCCBuilder.h>
#include <irene3/PatchIR/PatchIROps.h>
#include <irene3/PhysicalLocationDecoder.h>
#include <irene3/Transforms/PostPass.h>
#include <irene3/Transforms/WrapBBFuncPass.h>
#include <irene3/Transforms/WrapBBFuncPassCodegen.h>
#include <llvm/CodeGen/TargetRegisterInfo.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/PassManager.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <mlir/IR/Attributes.h>
#include <mlir/IR/BuiltinOps.h>
#include <mlir/Target/LLVMIR/TypeToLLVM.h>
#include <optional>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

namespace irene3
{

    struct OffAndIndex {
        std::int64_t offset;
        std::size_t arg_index;
    };

    class RestoreStackRelations : public PostWrappingPass< RestoreStackRelations > {
      private:
        std::unordered_map< std::string, OffAndIndex > reg_to_stack_offset_and_index;
        std::optional< RegionSummary > summ_sig;

        OffAndIndex GetReprStackOffset(patchir::RegisterAttr rattr, int64_t target_off);

      public:
        static llvm::StringRef name();

        llvm::PreservedAnalyses runOnBasicBlockFunction(
            anvill::Uid basic_block_addr,
            llvm::Function *F,
            llvm::ModuleAnalysisManager &AM,
            std::monostate tot);

        virtual llvm::FunctionType *GetSignature(anvill::Uid, const llvm::Function *) override;

        virtual void Transform(anvill::Uid, llvm::Function &) override;

        void RewriteCall(llvm::CallInst &cb, patchir::CallOp cop);

        RestoreStackRelations(
            llvm::LLVMContext &llcontext,
            mlir::ModuleOp mlir_module,
            const llvm::TargetRegisterInfo *reg_info,
            ModuleCallingConventions &ccmod,
            const IreneLoweringInterface &ILI)
            : PostWrappingPass< RestoreStackRelations >(
                llcontext, mlir_module, reg_info, ccmod, ILI) {}

        virtual llvm::CallBase *PopulateEntryBlock(
            anvill::Uid,
            llvm::IRBuilder<> &bldr,
            llvm::Function &target,
            llvm::Function *oldfunc) override;

        void finalize(std::monostate) {}
    };

} // namespace irene3