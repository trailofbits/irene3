#include <anvill/ABI.h>
#include <filesystem>
#include <iostream>
#include <irene3/DecompileSpec.h>
#include <irene3/TypeDecoder.h>
#include <irene3/Util.h>
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

    std::optional< std::int64_t > GetDepthForBlockEntry(
        const remill::Register* stack_reg, const anvill::BasicBlockContext& bbcont) {
        for (const auto& c : bbcont.GetStackOffsetsAtEntry().affine_equalities) {
            if (c.target_value.oredered_locs.size() == 1 && c.target_value.oredered_locs[0].reg
                && c.target_value.oredered_locs[0].reg == stack_reg) {
                return c.stack_offset;
            }
        }
        return std::nullopt;
    }

    std::optional< std::int64_t > GetDepthForBlockExit(
        const remill::Register* stack_reg, const anvill::FunctionDecl& decl, anvill::Uid uid) {
        auto nd = decl.cfg.at(uid);

        if (nd.outgoing_edges.empty()) {
            return 0;
        }

        for (auto e : nd.outgoing_edges) {
            // NOTE(Ian): This assumes that the stack depth at entry to all successor blocks is the
            // same otherwise we would have to have path sensitive variable expressions ie. (down cf
            // edge 1 the variable is at RSP+2 and the other RSP+4). This gets super messy and we
            // dont have downstream support. For now we only use entry offsets anyways, we need a
            // long convo about how to actually represent variable locations.
            auto blk_depth = GetDepthForBlockEntry(stack_reg, decl.GetBlockContext(e));
            if (blk_depth) {
                return blk_depth;
            }
        }

        return std::nullopt;
    }

    StackOffsets ComputeStackOffsets(
        const remill::Register* stack_reg, const anvill::FunctionDecl& decl, anvill::Uid uid) {
        auto cont       = decl.GetBlockContext(uid);
        auto ent_depth  = GetDepthForBlockEntry(stack_reg, cont);
        auto exit_depth = GetDepthForBlockExit(stack_reg, decl, uid);

        if (!ent_depth) {
            LOG(ERROR) << "Overriding entry depth with 0";
        }

        if (!exit_depth) {
            LOG(ERROR) << "Overriding exit depth with 0";
        }

        return { ent_depth.value_or(0), exit_depth.value_or(0) };
    }

    int64_t GetStackOffset(const remill::Arch& arch, const anvill::SpecStackOffsets& stack_offs) {
        auto sp_reg = arch.RegisterByName(arch.StackPointerRegisterName());
        for (auto& eq : stack_offs.affine_equalities) {
            if (eq.target_value.oredered_locs.size() != 1) {
                continue;
            }

            if (eq.target_value.oredered_locs[0].mem_reg) {
                continue;
            }

            if (eq.target_value.oredered_locs[0].reg == sp_reg) {
                return eq.stack_offset;
            }
        }
        LOG(ERROR) << "Couldn't find stack pointer";
        return 0;
    }
} // namespace irene3
