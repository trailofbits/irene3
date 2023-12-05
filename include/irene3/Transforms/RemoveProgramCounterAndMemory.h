#pragma once

#include "irene3/Transforms/WrapBBFuncPassCodegen.h"

#include <anvill/Declarations.h>
#include <anvill/Lifters.h>
#include <anvill/Passes/BasicBlockPass.h>
#include <irene3/Transforms/ModuleBBPass.h>
#include <irene3/Transforms/WrapBBFuncPass.h>
#include <llvm/IR/PassManager.h>

namespace irene3
{

    class RemoveProgramCounterAndMemory final
        : public WrapBBFuncPassCodegen< RemoveProgramCounterAndMemory > {
      public:
        static llvm::StringRef name();

        RemoveProgramCounterAndMemory(anvill::BasicBlockContexts &contexts)
            : WrapBBFuncPassCodegen< RemoveProgramCounterAndMemory >(contexts) {}

        virtual llvm::FunctionType *GetSignature(const BBInfo &, const llvm::Function *) override;

        virtual void Transform(const BBInfo &, llvm::Function &) override;

        virtual llvm::CallBase *PopulateEntryBlock(
            const BBInfo &,
            llvm::IRBuilder<> &bldr,
            llvm::Function &target,
            llvm::Function *oldfunc) override;
    };
} // namespace irene3
