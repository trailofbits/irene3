#include <filesystem>
#include <irene3/DecompileSpec.h>
#include <irene3/TypeDecoder.h>
#include <llvm/IR/GlobalVariable.h>
#include <vector>

namespace irene3
{
    // Produces a default decompilation job builder from a path to an anvill spec.
    rellic::Result< SpecDecompilationJobBuilder, std::string > ProtobufPathToDecompilationBuilder(
        const std::filesystem::path& input_spec,
        bool propagate_types,
        bool args_as_locals,
        TypeDecoder& type_decoder);

    // Gets pc metadata repersented in irene3 by the "pc" metadata kind.
    std::optional< uint64_t > GetPCMetadata(const llvm::Value* value);

    std::vector< llvm::GlobalVariable* > UsedGlobalVars(llvm::Function* func);
} // namespace irene3