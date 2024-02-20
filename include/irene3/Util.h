#pragma once

#include <cstdint>
#include <filesystem>
#include <irene3/DecompileSpec.h>
#include <irene3/IreneLoweringInterface.h>
#include <irene3/PatchIR/PatchIRAttrs.h>
#include <irene3/PatchIR/PatchIRDialect.h>
#include <irene3/PatchIR/PatchIROps.h>
#include <irene3/TypeDecoder.h>
#include <llvm/CodeGen/MachineValueType.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/LLVMContext.h>
#include <mlir/Dialect/LLVMIR/LLVMDialect.h>
#include <mlir/IR/BuiltinOps.h>
#include <mlir/IR/MLIRContext.h>
#include <mlir/Parser/Parser.h>
#include <mlir/Support/LLVM.h>
#include <unordered_set>
#include <variant>
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

    template< class... Ts >
    struct overload : Ts... {
        using Ts::operator()...;
    };

    template< class... Ts >
    overload(Ts...) -> overload< Ts... >;

    llvm::IntegerType* AddressType(const llvm::Module* mod);
    llvm::FunctionType* CreateExitingFunctionTy(
        llvm::LLVMContext& context, const RegionSummary& lv);
    llvm::FunctionType* CreateRegionSigFuncTy(
        llvm::LLVMContext& context, const RegionSignature& sig);
    extern const std::string kSSAedBlockFunctionMetadata;
    using LowLoc = std::variant<
        irene3::patchir::MemoryIndirectAttr,
        irene3::patchir::RegisterAttr,
        irene3::patchir::MemoryAttr >;
    struct CallOpInfo {
        std::vector< LowLoc > at_entry;
        std::vector< LowLoc > at_exit;

        std::int64_t entry_stack_offset;
        std::int64_t exit_stack_offset;

        explicit CallOpInfo(irene3::patchir::CallOp op);
    };

    // Produces a default decompilation job builder from a path to an anvill spec.
    rellic::Result< SpecDecompilationJobBuilder, std::string > ProtobufPathToDecompilationBuilder(
        const std::filesystem::path& input_spec,
        bool propagate_types,
        bool args_as_locals,
        bool unsafe_stack_locations,
        TypeDecoder& type_decoder);

    void SetPCMetadata(llvm::GlobalObject* value, uint64_t pc);

    void SetRelativeCallMetada(llvm::CallBase* cb);

    bool IsRelativeCall(llvm::CallBase* cb);
    // Gets pc metadata repersented in irene3 by the "pc" metadata kind.
    std::optional< uint64_t > GetPCMetadata(const llvm::Value* value);

    template< typename T >
    std::vector< T* > UsedGlobalValue(llvm::Function* func) {
        std::unordered_set< T* > vars;
        for (auto& gv : func->getParent()->global_values()) {
            for (auto use : gv.users()) {
                if (T* casted_val = llvm::dyn_cast< T >(&gv)) {
                    if (auto insn = llvm::dyn_cast< llvm::Instruction >(use)) {
                        if (insn->getFunction() == func) {
                            vars.insert(casted_val);
                        }
                    }
                }
            }
        }
        return { vars.begin(), vars.end() };
    }

    template< typename T >
    std::vector< T* > UsedGlobalValue(
        llvm::Function* func, const std::unordered_set< std::string >& required_globals) {
        std::unordered_set< T* > vars;
        for (auto& gv : func->getParent()->global_values()) {
            for (auto use : gv.users()) {
                if (T* casted_val = llvm::dyn_cast< T >(&gv)) {
                    if (auto insn = llvm::dyn_cast< llvm::Instruction >(use)) {
                        if (insn->getFunction() == func) {
                            vars.insert(casted_val);
                        }
                    } else if (required_globals.count(casted_val->getName().str())) {
                        vars.insert(casted_val);
                    }
                }
            }
        }
        return { vars.begin(), vars.end() };
    }

    LowLoc ConvertToVariant(mlir::Attribute attr);

    llvm::Function* GetOrCreateGotoInstrinsic(llvm::Module* mod, llvm::IntegerType* addr_ty);

    std::optional< std::int64_t > GetDepthForBlockEntry(
        const remill::Register* stack_reg, const anvill::BasicBlockContext& bbcont);
    std::optional< std::int64_t > GetDepthForBlockExit(
        const remill::Register* stack_reg, const anvill::FunctionDecl& decl, anvill::Uid uid);

    struct StackOffsets {
        std::int64_t stack_depth_at_entry;
        std::int64_t stack_depth_at_exit;
    };
    StackOffsets ComputeStackOffsets(
        const remill::Register* stack_reg, const anvill::FunctionDecl& decl, anvill::Uid uid);
    int64_t GetStackOffset(const remill::Arch& arch, const anvill::SpecStackOffsets& stack_offs);

    struct FlatAddr {
        uint64_t addr    = 0;
        int64_t disp     = 0;
        bool is_external = false;
    };

    FlatAddr BinaryAddrToFlat(const anvill::MachineAddr& addr);

    anvill::MachineAddr MachineAddrFromFlatValues(
        uint64_t address, std::int64_t disp, bool is_external);

    void PatchIRContext(mlir::MLIRContext& context);

    llvm::Type* ConvertMVT(llvm::LLVMContext& context, llvm::MVT svt);
} // namespace irene3