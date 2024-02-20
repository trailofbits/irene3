#pragma once

#include <anvill/Declarations.h>
#include <irene3/ILIMixin.h>
#include <irene3/LowLocCCBuilder.h>
#include <irene3/PatchIR/PatchIROps.h>
#include <irene3/PhysicalLocationDecoder.h>
#include <irene3/Transforms/WrapBBFuncPass.h>
#include <irene3/Transforms/WrapBBFuncPassCodegen.h>
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

    struct LowVar {
        LowAssignment assignment;
        size_t high_index;
    };

    struct Liftable {
        llvm::Type *base_type;
        std::vector< llvm::MVT > population_by_component;
    };

    struct LoweredVariables {
        std::vector< LowVar > at_entry;
        std::vector< LowVar > at_exit;
    };

    class PostPass : protected ILIMixin< PostPass > {
        friend class ILIMixin< PostPass >;

      protected:
        mlir::ModuleOp mlir_module;
        std::unordered_map< anvill::Uid, patchir::CallOp > uid_to_caller;
        const llvm::TargetRegisterInfo *reg_info;
        RegTable rtable;
        mlir::LLVM::TypeToLLVMIRTranslator type_decoder;
        ModuleCallingConventions &collected_ccs;
        const IreneLoweringInterface &ILI;

      public:
        PostPass(
            llvm::LLVMContext &llcontext,
            mlir::ModuleOp mlir_module,
            const llvm::TargetRegisterInfo *reg_info,
            ModuleCallingConventions &ccmod,
            const IreneLoweringInterface &ILI)
            : mlir_module(mlir_module)
            , reg_info(reg_info)
            , type_decoder(llcontext)
            , collected_ccs(ccmod)
            , ILI(ILI) {
            this->PopulateUidToRegion();
            this->rtable.Populate(reg_info);
        }

        void PopulateUidToRegion() {
            for (auto f : this->mlir_module.template getOps< irene3::patchir::FunctionOp >()) {
                for (auto r : f.template getOps< irene3::patchir::RegionOp >()) {
                    auto c = firstOp< patchir::RegionOp, patchir::CallOp >(r);
                    if (c) {
                        this->uid_to_caller.insert({ { r.getUid() }, *c });
                    }
                }
            }
        }
    };

} // namespace irene3