#include <filesystem>
#include <iostream>
#include <irene3/DecompileSpec.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/MemoryBuffer.h>
#include <rellic/Result.h>
#include <remill/BC/Error.h>
#include <remill/BC/Util.h>
#include <sstream>

namespace irene3
{
    rellic::Result< SpecDecompilationJobBuilder, std::string > JSONPathToDecompilationBuilder(
        const std::filesystem::path& input_spec) {
        auto maybe_buff = llvm::MemoryBuffer::getFileOrSTDIN(input_spec.c_str());
        if (remill::IsError(maybe_buff)) {
            std::stringstream ss;
            ss << "Unable to read JSON spec file '" << input_spec
               << "': " << remill::GetErrorString(maybe_buff) << std::endl;
            return ss.str();
        }
        const std::unique_ptr< llvm::MemoryBuffer >& buff = remill::GetReference(maybe_buff);

        auto maybe_json = llvm::json::parse(buff->getBuffer());
        if (remill::IsError(maybe_json)) {
            std::stringstream ss;
            ss << "Unable to parse JSON spec file '" << input_spec
               << "': " << remill::GetErrorString(maybe_json) << std::endl;
            return ss.str();
        }

        llvm::json::Value v = maybe_json.get();

        return SpecDecompilationJobBuilder::CreateDefaultBuilder(v);
    }

    std::optional< uint64_t > GetPCMetadata(const llvm::Value* value) {
        if (!value) {
            return std::nullopt;
        }

        llvm::MDNode* pc = nullptr;
        if (auto obj = llvm::dyn_cast< llvm::GlobalObject >(value)) {
            pc = obj->getMetadata("pc");

        } else if (auto inst = llvm::dyn_cast< llvm::Instruction >(value)) {
            pc = inst->getMetadata("pc");
        }

        if (!pc) {
            return std::nullopt;
        }

        auto& cop = pc->getOperand(0U);
        auto cval = llvm::cast< llvm::ConstantAsMetadata >(cop)->getValue();

        return llvm::cast< llvm::ConstantInt >(cval)->getValue().getZExtValue();
    }
} // namespace irene3
