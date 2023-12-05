#pragma once

#include "anvill/Declarations.h"
#include "irene3/PatchIR/PatchIROps.h"
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

    template< typename T, typename R >
    std::optional< R > firstOp(T x) {
        auto rng = x.template getOps< R >();
        if (rng.empty()) {
            return std::nullopt;
        }

        return *rng.begin();
    }

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

    template< typename T >
    class PostPass : public WrapBBFuncPass< T > {
      protected:
        mlir::ModuleOp mlir_module;
        std::unordered_map< anvill::Uid, patchir::CallOp > uid_to_caller;
        PhysTypeTranslator tt_translator;
        mlir::LLVM::TypeToLLVMIRTranslator type_decoder;
        ModuleCallingConventions &collected_ccs;

      public:
        PostPass(
            llvm::LLVMContext &llcontext,
            mlir::ModuleOp mlir_module,
            const llvm::TargetRegisterInfo *reg_info,
            ModuleCallingConventions &ccmod)
            : WrapBBFuncPass< T >()
            , mlir_module(mlir_module)
            , tt_translator(reg_info)
            , type_decoder(llcontext)
            , collected_ccs(ccmod) {
            this->PopulateUidToRegion();
        }

        LoweredVariables LowerVariables(patchir::CallOp cop) {
            LoweredVariables lv;
            size_t high_index = 0;
            for (auto arg : cop.getArgs()) {
                auto attr                                 = arg.getDefiningOp();
                auto vop                                  = mlir::cast< patchir::ValueOp >(attr);
                patchir::LowValuePointerType wrapper_type = vop.getType();
                auto highty  = this->type_decoder.translateType(wrapper_type.getElement());
                auto collect = [](std::vector< LowVar > &target, std::vector< LowVar > v) {
                    target.insert(target.end(), v.begin(), v.end());
                };
                if (vop.getAtEntry()) {
                    collect(
                        lv.at_entry, this->LowerVariable(*vop.getAtEntry(), high_index, highty));
                }
                if (vop.getAtExit()) {
                    collect(lv.at_exit, this->LowerVariable(*vop.getAtExit(), high_index, highty));
                }
                high_index += 1;
            }

            return lv;
        }

        std::vector< LowVar > LowerVariable(
            mlir::Attribute attr, size_t hv_index, llvm::Type *high_ty) {
            LowLoc v   = ConvertToVariant(attr);
            auto split = this->tt_translator.ComputeComponentAssignments(high_ty, v);
            if (!split) {
                LOG(FATAL) << "failed to split componenets";
            }

            std::vector< LowVar > lvs;
            size_t byte_offset = 0;
            for (auto low_ty : *split) {
                lvs.push_back({
                    {byte_offset, low_ty},
                    hv_index
                });
                CHECK(low_ty.getFixedSizeInBits() % 8 == 0);
                auto bytes = low_ty.getFixedSizeInBits() / 8;
                byte_offset += bytes;
            }
            return lvs;
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