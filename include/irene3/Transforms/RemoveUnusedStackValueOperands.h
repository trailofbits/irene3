#pragma once

#include <glog/logging.h>
#include <irene3/PatchIR/PatchIRAttrs.h>
#include <irene3/PatchIR/PatchIRDialect.h>
#include <irene3/PatchIR/PatchIROps.h>
#include <irene3/PhysicalLocationDecoder.h>
#include <mlir/Dialect/LLVMIR/LLVMDialect.h>
#include <mlir/Dialect/LLVMIR/LLVMTypes.h>
#include <mlir/IR/Attributes.h>
#include <mlir/IR/BuiltinOps.h>
#include <mlir/IR/Value.h>
#include <mlir/Pass/Pass.h>
#include <mlir/Support/LLVM.h>
#include <unordered_set>
#include <vector>

namespace irene3
{
    class RemoveUnusedStackValueOperands
        : public mlir::
              PassWrapper< RemoveUnusedStackValueOperands, mlir::OperationPass< mlir::ModuleOp > > {
      public:
        RemoveUnusedStackValueOperands(RegTable supported_regs)
            : supported_regs(std::move(supported_regs)) {}

      private:
        RegTable supported_regs;

        bool isUnsupportedRegister(std::optional< mlir::Attribute > attr) {
            if (!attr) {
                return false;
            }

            if (auto reg = mlir::dyn_cast< patchir::RegisterAttr >(*attr)) {
                auto is_unsupported = !this->supported_regs.lookup(reg.getReg().str()).has_value();
                LOG_IF(ERROR, is_unsupported)
                    << "Encountered unsupported reg: " << reg.getReg().str();
                return is_unsupported;
            }
            return false;
        }

        void rewriteCall(patchir::CallOp op, mlir::ModuleOp mod) {
            auto called_func
                = mlir::cast< mlir::LLVM::LLVMFuncOp >(mod.lookupSymbol(op.getCallee()));

            if (!called_func.getCallableRegion()) {
                return;
            }

            std::vector< bool > argmask;
            for (size_t ind = 0; ind < op.getArgs().size(); ind++) {
                auto arg                 = op.getArgs()[ind];
                auto vop                 = mlir::cast< patchir::ValueOp >(arg.getDefiningOp());
                auto has_unsupported_reg = isUnsupportedRegister(vop.getAtEntry())
                                           || isUnsupportedRegister(vop.getAtExit());

                auto is_stack_only
                    = (!vop.getAtEntry().has_value()
                       || mlir::isa< patchir::MemoryIndirectAttr >(*vop.getAtEntry()))
                      && (!vop.getAtExit().has_value()
                          || mlir::isa< patchir::MemoryIndirectAttr >(*vop.getAtExit()));
                auto x = called_func.getCallableRegion()->getArguments()[ind];
                argmask.push_back(x.getUses().empty() && (has_unsupported_reg || is_stack_only));
            }

            // rewrite function
            auto fty = called_func.getFunctionType();
            std::vector< mlir::Type > ptypes;
            size_t erased = 0;
            for (size_t ind = 0; ind < argmask.size(); ind++) {
                if (argmask[ind]) {
                    op.getArgsMutable().erase(ind - erased);
                    called_func.getCallableRegion()->eraseArgument(ind - erased);
                    erased += 1;
                } else {
                    ptypes.push_back(fty.getParamType(ind));
                }
            }

            called_func.setFunctionType(
                mlir::LLVM::LLVMFunctionType::get(fty.getReturnType(), ptypes, fty.isVarArg()));
        };

      public:
        void runOnOperation() {
            auto op = getOperation();
            for (auto fop : op.getOps< patchir::FunctionOp >()) {
                for (auto rop : fop.getOps< patchir::RegionOp >()) {
                    for (auto cop : rop.getOps< patchir::CallOp >()) {
                        rewriteCall(cop, op);
                    }
                }
            }
        }
    };
} // namespace irene3