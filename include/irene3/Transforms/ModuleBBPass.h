#pragma once

#include "anvill/Declarations.h"

#include <anvill/Passes/BasicBlockPass.h>
#include <anvill/Utils.h>
#include <functional>
#include <glog/logging.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <utility>
#include <vector>

namespace irene3
{
    template< typename T, typename S >
    class ModuleBBPass : public llvm::PassInfoMixin< T > {
      private:
      public:
        ModuleBBPass() {}

        static llvm::StringRef name(void) { return T::name(); }

        llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &MAM) {
            std::vector< std::tuple< anvill::Uid, llvm::Function * > > v;

            auto &bb_pass = *static_cast< T * >(this);
            for (auto &f : M.functions()) {
                auto bbaddr = anvill::GetBasicBlockUid(&f);
                if (bbaddr.has_value()) {
                    anvill::Uid addr = *bbaddr;
                    v.push_back({ addr, &f });
                }
            }

            S state;
            auto curr_res = llvm::PreservedAnalyses::all();
            for (auto [bbaddr, f] : v) {
                curr_res.intersect(bb_pass.runOnBasicBlockFunction(bbaddr, f, MAM, state));
            }

            bb_pass.finalize(state);

            return curr_res;
        }
    };

} // namespace irene3