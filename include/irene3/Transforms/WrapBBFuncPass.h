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
#include <llvm/ADT/StringRef.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <vector>

namespace irene3
{

    template< typename T >
    concept HasName = requires { T::name(); };

    using WrapBBFuncState = std::vector< std::pair< llvm::Function *, llvm::Function * > >;

    template< typename T >
    class WrapBBFuncPass : public ModuleBBPass< WrapBBFuncPass< T >, WrapBBFuncState > {
      public:
        virtual llvm::FunctionType *GetSignature(anvill::Uid, const llvm::Function *) = 0;

        virtual void Transform(anvill::Uid, llvm::Function &) {}

        virtual llvm::CallBase *PopulateEntryBlock(
            anvill::Uid, llvm::IRBuilder<> &bldr, llvm::Function &target, llvm::Function *oldfunc)
            = 0;

        static llvm::StringRef name(void) { return T::name(); }

        llvm::PreservedAnalyses runOnBasicBlockFunction(
            anvill::Uid basic_block_addr,
            llvm::Function *F,
            llvm::ModuleAnalysisManager &AM,
            std::vector< std::pair< llvm::Function *, llvm::Function * > > &tot) {
            llvm::FunctionType *fty = this->GetSignature(basic_block_addr, F);
            llvm::Function &new_f   = *llvm::Function::Create(
                fty, llvm::GlobalValue::ExternalLinkage, F->getName() + T::name(), F->getParent());

            auto ent_bb = llvm::BasicBlock::Create(F->getContext(), "entry", &new_f);
            llvm::IRBuilder<> bldr(ent_bb);
            llvm::CallBase *call_inst = this->PopulateEntryBlock(basic_block_addr, bldr, new_f, F);
            llvm::InlineFunctionInfo info;
            auto res = llvm::InlineFunction(*call_inst, info);
            CHECK(res.isSuccess());
            this->Transform(basic_block_addr, new_f);
            tot.push_back({ F, &new_f });
            return llvm::PreservedAnalyses::none();
        }

        void finalize(const std::vector< std::pair< llvm::Function *, llvm::Function * > > &v) {
            for (const auto &[old, repl] : v) {
                repl->setMetadata(
                    anvill::kBasicBlockUidMetadata,
                    old->getMetadata(anvill::kBasicBlockUidMetadata));
                auto nm = std::string(old->getName());
                old->replaceAllUsesWith(llvm::UndefValue::get(old->getType()));
                old->eraseFromParent();
                repl->setName(nm);
            }
        }
    };

} // namespace irene3