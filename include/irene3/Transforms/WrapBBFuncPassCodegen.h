/**
 * Abstraction over passes that:
 * 1. Find all BB funcs
 * 2. Generate SIG
 * 3. Create new caller
 * 4. (OPTIONAL) perform a transform
 * 5. inline
 * 6. remove old metadata
 * 7. attach new metadata
 * 8. delete old functions
 */

#pragma once

#include "anvill/ABI.h"
#include "anvill/Declarations.h"

#include <concepts>
#include <irene3/Transforms/ModuleBBPass.h>
#include <irene3/Transforms/WrapBBFuncPass.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <optional>
#include <vector>

namespace irene3
{
    struct BBInfo {
        anvill::Uid uid;
        const anvill::CodeBlock &cb;
        const anvill::BasicBlockContext &context;
        const anvill::FunctionDecl &fdecl;
    };

    template< typename T >
    class WrapBBFuncPassCodegen : public WrapBBFuncPass< WrapBBFuncPassCodegen< T > > {
      private:
        const anvill::BasicBlockContexts &contexts;
        std::optional< BBInfo > binfo;

      public:
        WrapBBFuncPassCodegen(anvill::BasicBlockContexts &contexts)
            : contexts(contexts) {}

        virtual llvm::FunctionType *GetSignature(const BBInfo &, const llvm::Function *) = 0;

        virtual void Transform(const BBInfo &, llvm::Function &) {}

        virtual llvm::CallBase *PopulateEntryBlock(
            const BBInfo &,
            llvm::IRBuilder<> &bldr,
            llvm::Function &target,
            llvm::Function *oldfunc)
            = 0;

        virtual llvm::FunctionType *GetSignature(
            anvill::Uid uid, const llvm::Function *f) override {
            const anvill::BasicBlockContext &ctx = *contexts.GetBasicBlockContextForUid(uid);
            const anvill::FunctionDecl &decl
                = contexts.GetFunctionAtAddress(ctx.GetParentFunctionAddress());
            const anvill::CodeBlock &cb = decl.cfg.at(uid);
            BBInfo binfo                = { uid, cb, ctx, decl };
            this->binfo.emplace(std::move(binfo));
            return this->GetSignature(*this->binfo, f);
        }

        virtual void Transform(anvill::Uid uid, llvm::Function &F) override {
            return this->Transform(*this->binfo, F);
        }

        virtual llvm::CallBase *PopulateEntryBlock(
            anvill::Uid,
            llvm::IRBuilder<> &bldr,
            llvm::Function &target,
            llvm::Function *oldfunc) override {
            return this->PopulateEntryBlock(*this->binfo, bldr, target, oldfunc);
        }

        static llvm::StringRef name(void) { return T::name(); }
    };

} // namespace irene3