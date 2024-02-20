#pragma once

#include "irene3/Transforms/PostPass.h"

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

    template< typename T >
    class PostWrappingPass
        : protected PostPass
        , public WrapBBFuncPass< T > {
      public:
        PostWrappingPass(
            llvm::LLVMContext &llcontext,
            mlir::ModuleOp mlir_module,
            const llvm::TargetRegisterInfo *reg_info,
            ModuleCallingConventions &ccmod,
            const IreneLoweringInterface &ILI)
            : PostPass(llcontext, mlir_module, reg_info, ccmod, ILI)
            , WrapBBFuncPass< T >() {}
    };

} // namespace irene3