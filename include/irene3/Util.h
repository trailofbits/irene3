#include <filesystem>
#include <irene3/DecompileSpec.h>
#include <irene3/TypeDecoder.h>
#include <llvm/IR/GlobalVariable.h>
#include <unordered_set>
#include <vector>

namespace irene3
{
    // Produces a default decompilation job builder from a path to an anvill spec.
    rellic::Result< SpecDecompilationJobBuilder, std::string > ProtobufPathToDecompilationBuilder(
        const std::filesystem::path& input_spec,
        bool propagate_types,
        bool args_as_locals,
        bool unsafe_stack_locations,
        TypeDecoder& type_decoder);

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

    llvm::Function* GetOrCreateGotoInstrinsic(llvm::Module* mod, llvm::IntegerType* addr_ty);

    std::optional< std::int64_t > GetDepthForBlockEntry(
        const remill::Register* stack_reg, const anvill::BasicBlockContext& bbcont);
    std::optional< std::int64_t > GetDepthForBlockExit(
        const remill::Register* stack_reg, const anvill::FunctionDecl& decl, uint64_t bbaddr);

    struct StackOffsets {
        std::int64_t stack_depth_at_entry;
        std::int64_t stack_depth_at_exit;
    };
    StackOffsets ComputeStackOffsets(
        const remill::Register* stack_reg, const anvill::FunctionDecl& decl, uint64_t bbaddr);
    int64_t GetStackOffset(const remill::Arch& arch, const anvill::SpecStackOffsets& stack_offs);
} // namespace irene3