#pragma once

#include "irene3/IreneLoweringInterface.h"
#include "irene3/Transforms/PostWrappingPass.h"

#include <anvill/Declarations.h>
#include <irene3/LowLocCCBuilder.h>
#include <irene3/PatchIR/PatchIRAttrs.h>
#include <irene3/PatchIR/PatchIRDialect.h>
#include <irene3/PatchIR/PatchIROps.h>
#include <irene3/PhysicalLocationDecoder.h>
#include <irene3/Transforms/PostPass.h>
#include <irene3/Transforms/WrapBBFuncPass.h>
#include <irene3/Transforms/WrapBBFuncPassCodegen.h>
#include <irene3/Util.h>
#include <llvm/CodeGen/TargetRegisterInfo.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalObject.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/ValueMap.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <mlir/IR/Attributes.h>
#include <mlir/IR/BuiltinAttributes.h>
#include <mlir/IR/BuiltinOps.h>
#include <mlir/Support/LLVM.h>
#include <mlir/Target/LLVMIR/TypeToLLVM.h>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace irene3
{
    class ReplaceRelReferences : public PostWrappingPass< ReplaceRelReferences > {
      private:
        const llvm::TargetRegisterInfo *reg_info;
        std::optional< irene3::patchir::RegisterAttr > image_base_storage;
        std::vector< irene3::patchir::RegisterAttr > free_reg_list;
        llvm::ValueMap< llvm::GlobalObject *, FlatAddr > addressing_table;
        uint64_t image_base;

      public:
        ReplaceRelReferences(
            llvm::LLVMContext &llcontext,
            mlir::ModuleOp mlir_module,
            const llvm::TargetRegisterInfo *reg_info,
            ModuleCallingConventions &ccmod,
            const IreneLoweringInterface &ILI)
            : PostWrappingPass< ReplaceRelReferences >(llcontext, mlir_module, reg_info, ccmod, ILI)
            , reg_info(reg_info) {
            this->image_base
                = mlir::cast< mlir::IntegerAttr >(
                      mlir_module->getAttr(patchir::PatchIRDialect::getImageBaseAttrName()))
                      .getUInt();
        }

        static llvm::StringRef name();

        irene3::patchir::RegisterAttr CreateAddrTypedReg(
            llvm::Module *,
            const std::vector< LowLoc > &live_entries,
            std::vector< irene3::patchir::RegisterAttr > additional_regs);

        virtual llvm::FunctionType *GetSignature(anvill::Uid, const llvm::Function *) override;

        virtual void Transform(anvill::Uid, llvm::Function &) override;

        std::optional< std::string > GetImageBaseReg() const;

        uint64_t GetBaseImage() const { return this->image_base; }

        std::vector< irene3::patchir::RegisterAttr > getFreeRegsList() const {
            return this->free_reg_list;
        }

        virtual llvm::CallBase *PopulateEntryBlock(
            anvill::Uid,
            llvm::IRBuilder<> &bldr,
            llvm::Function &target,
            llvm::Function *oldfunc) override;
    };

} // namespace irene3