#include "irene3/IreneLoweringInterface.h"

#include <algorithm>
#include <anvill/ABI.h>
#include <anvill/Declarations.h>
#include <filesystem>
#include <iostream>
#include <irene3/DecompileSpec.h>
#include <irene3/PatchIR/PatchIROps.h>
#include <irene3/TypeDecoder.h>
#include <irene3/Util.h>
#include <llvm/CodeGen/MachineValueType.h>
#include <llvm/IR/Attributes.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Metadata.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/MemoryBuffer.h>
#include <mlir/Dialect/DLTI/DLTI.h>
#include <mlir/Support/LLVM.h>
#include <mlir/Target/LLVMIR/Dialect/Builtin/BuiltinToLLVMIRTranslation.h>
#include <mlir/Target/LLVMIR/Dialect/LLVMIR/LLVMToLLVMIRTranslation.h>
#include <rellic/Result.h>
#include <remill/BC/Error.h>
#include <remill/BC/Util.h>
#include <sstream>

namespace irene3
{

    const std::string kSSAedBlockFunctionMetadata("ssaed_bbfunc");

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

    llvm::IntegerType* AddressType(const llvm::Module* mod) {
        return llvm::IntegerType::get(
            mod->getContext(), mod->getDataLayout().getPointerSizeInBits());
    }
    void SetPCMetadata(llvm::GlobalObject* value, uint64_t pc) {
        auto& context      = value->getContext();
        auto& dl           = value->getParent()->getDataLayout();
        auto* address_type = llvm::Type::getIntNTy(context, dl.getPointerSizeInBits(0));
        auto* cam  = llvm::ConstantAsMetadata::get(llvm::ConstantInt::get(address_type, pc));
        auto* node = llvm::MDNode::get(context, cam);
        value->setMetadata("pc", node);
    }

    void SetRelativeCallMetada(llvm::CallBase* cb) {
        cb->setMetadata("is_rel", llvm::MDNode::get(cb->getContext(), {}));
    }

    bool IsRelativeCall(llvm::CallBase* cb) { return cb->getMetadata("is_rel"); }

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
            if (c.target_value.ordered_locs.size() == 1 && c.target_value.ordered_locs[0].reg
                && c.target_value.ordered_locs[0].reg == stack_reg) {
                return c.stack_offset;
            }
        }
        return std::nullopt;
    }

    llvm::FunctionType* CreateRegionSigFuncTy(
        llvm::LLVMContext& context, const RegionSignature& sig) {
        std::vector< llvm::Type* > args;

        for (const auto& comp : sig.Components()) {
            for (const auto& ptr : comp) {
                auto ty = ConvertMVT(context, ptr->GetMVT());
                args.push_back(ty);
            }
        }
        return llvm::FunctionType::get(llvm::Type::getVoidTy(context), args, false);
    }

    llvm::FunctionType* CreateExitingFunctionTy(
        llvm::LLVMContext& context, const RegionSummary& lv) {
        std::vector< llvm::Type* > args;
        return CreateRegionSigFuncTy(context, lv.at_exit);
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
            if (eq.target_value.ordered_locs.size() != 1) {
                continue;
            }

            if (eq.target_value.ordered_locs[0].mem_reg) {
                continue;
            }

            if (eq.target_value.ordered_locs[0].reg == sp_reg) {
                return eq.stack_offset;
            }
        }
        LOG(ERROR) << "Couldn't find stack pointer";
        return 0;
    }

    LowLoc ConvertToVariant(mlir::Attribute attr) {
        attr.dump();
        if (irene3::patchir::MemoryAttr mem = mlir::dyn_cast< irene3::patchir::MemoryAttr >(attr)) {
            return mem;
        } else if (auto mem_ind = llvm::dyn_cast< irene3::patchir::MemoryIndirectAttr >(attr)) {
            return mem_ind;
        } else if (auto reg = mlir::dyn_cast< irene3::patchir::RegisterAttr >(attr)) {
            return reg;
        }

        LOG(FATAL) << "Expected PatchIR_LowLocAttr";
    }

    CallOpInfo::CallOpInfo(irene3::patchir::CallOp op) {
        auto reg                 = mlir::dyn_cast< irene3::patchir::RegionOp >(op->getParentOp());
        this->entry_stack_offset = reg.getStackOffsetEntryBytesAttr().getSInt();
        this->exit_stack_offset  = reg.getStackOffsetExitBytesAttr().getSInt();
        for (auto op : op->getOperands()) {
            if (auto val = mlir::dyn_cast< irene3::patchir::ValueOp >(op.getDefiningOp())) {
                auto at_ent  = val.getAtEntry();
                auto at_exit = val.getAtExit();
                if (at_ent) {
                    this->at_entry.push_back(ConvertToVariant(*at_ent));
                }
                if (at_exit) {
                    this->at_exit.push_back(ConvertToVariant(*at_exit));
                }
            }
        }
    }

    anvill::MachineAddr MachineAddrFromFlatValues(
        uint64_t address, std::int64_t disp, bool is_external) {
        if (is_external) {
            return address;
        }

        return anvill::RelAddr{ address, disp };
    }

    FlatAddr BinaryAddrToFlat(const anvill::MachineAddr& addr) {
        FlatAddr res;
        if (std::holds_alternative< anvill::RelAddr >(addr)) {
            auto rel        = std::get< anvill::RelAddr >(addr);
            res.addr        = rel.vaddr;
            res.disp        = rel.disp;
            res.is_external = true;
        } else if (std::holds_alternative< uint64_t >(addr)) {
            res.addr = std::get< uint64_t >(addr);
        }
        return res;
    }

    void PatchIRContext(mlir::MLIRContext& context) {
        mlir::DialectRegistry registry;
        registry.insert< irene3::patchir::PatchIRDialect >();
        registry.insert< mlir::LLVM::LLVMDialect >();
        registry.insert< mlir::DLTIDialect >();
        context.appendDialectRegistry(registry);

        mlir::registerBuiltinDialectTranslation(context);
        mlir::registerLLVMDialectTranslation(context);
    }

    llvm::Type* ConvertMVT(llvm::LLVMContext& context, llvm::MVT svt) {
        if (svt.isInteger() && svt.isScalarInteger()) {
            return llvm::IntegerType::get(context, svt.getFixedSizeInBits());
        } else if(svt.isVector() && svt.isInteger()) {
            // hack we should build up more types.
            return llvm::VectorType::get(llvm::IntegerType::get(context,svt.getVectorElementType().getSizeInBits()), svt.getVectorElementCount());
        } else if (svt.isFloatingPoint()) {
            switch (svt.getFixedSizeInBits()) {
                case 16: return llvm::Type::getHalfTy(context);
                case 32: return llvm::Type::getFloatTy(context);
                case 64: return llvm::Type::getDoubleTy(context);
                case 128: return llvm::Type::getFP128Ty(context);
                default: {
                    LOG(FATAL) << "Unknown float " << svt.getFixedSizeInBits();
                    return nullptr;
                };
            }
        }

        std::string s;
        llvm::raw_string_ostream os(s);
        svt.print(os);
        LOG(FATAL) << "unable to convert mvt: " << s;
    }

} // namespace irene3
