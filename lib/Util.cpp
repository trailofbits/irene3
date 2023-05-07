#include <anvill/ABI.h>
#include <filesystem>
#include <iostream>
#include <irene3/DecompileSpec.h>
#include <irene3/TypeDecoder.h>
#include <llvm/IR/Attributes.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/MemoryBuffer.h>
#include <rellic/Result.h>
#include <remill/BC/Error.h>
#include <remill/BC/Util.h>
#include <sstream>

namespace irene3
{

    llvm::Function* GetOrCreateGotoInstrinsic(llvm::Module* mod, llvm::IntegerType* addr_ty) {
        auto fun = mod->getFunction(anvill::kAnvillGoto);
        if (fun) {
            return fun;
        }
        auto tgt_type
            = llvm::FunctionType::get(llvm::Type::getVoidTy(mod->getContext()), { addr_ty }, false);
        auto f = llvm::Function::Create(
            tgt_type, llvm::GlobalValue::ExternalLinkage, anvill::kAnvillGoto, mod);
        f->addFnAttr(llvm::Attribute::NoReturn);
        return f;
    }

    rellic::Result< SpecDecompilationJobBuilder, std::string > ProtobufPathToDecompilationBuilder(
        const std::filesystem::path& input_spec,
        bool propagate_types,
        bool args_as_locals,
        bool unsafe_stack_locations,
        TypeDecoder& type_decoder) {
        auto maybe_buff = llvm::MemoryBuffer::getFileOrSTDIN(input_spec.c_str());
        if (remill::IsError(maybe_buff)) {
            std::stringstream ss;
            ss << "Unable to read protobuf spec file '" << input_spec
               << "': " << remill::GetErrorString(maybe_buff) << std::endl;
            return ss.str();
        }
        const std::unique_ptr< llvm::MemoryBuffer >& buff = remill::GetReference(maybe_buff);

        return SpecDecompilationJobBuilder::CreateDefaultBuilder(
            buff->getBuffer().str(), propagate_types, args_as_locals, unsafe_stack_locations,
            type_decoder);
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
