#include <filesystem>
#include <irene3/DecompileSpec.h>

namespace irene3
{
    // Produces a default decompilation job builder from a path to an anvill spec.
    rellic::Result< SpecDecompilationJobBuilder, std::string > ProtobufPathToDecompilationBuilder(
        const std::filesystem::path& input_spec, bool propagate_types = true);

    // Gets pc metadata repersented in irene3 by the "pc" metadata kind.
    std::optional< uint64_t > GetPCMetadata(const llvm::Value* value);
} // namespace irene3