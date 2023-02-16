#include "SpecLayoutOverride.h"
#include "SpecTypeProvider.h"

#include <anvill/Lifters.h>
#include <anvill/Optimize.h>
#include <anvill/Providers.h>
#include <anvill/Specification.h>
#include <anvill/Utils.h>
#include <clang/AST/AST.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Stmt.h>
#include <clang/Basic/LLVM.h>
#include <clang/Tooling/Tooling.h>
#include <glog/logging.h>
#include <irene3/DecompileSpec.h>
#include <irene3/TypeDecoder.h>
#include <irene3/Util.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Value.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/raw_ostream.h>
#include <memory>
#include <optional>
#include <rellic/Decompiler.h>
#include <remill/Arch/Arch.h>
#include <remill/BC/Util.h>
#include <remill/BC/Version.h>
#include <stdint.h>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace irene3
{

    std::optional< uint64_t > ProvenanceInfo::AddressOfDecl(const clang::ValueDecl* decl) {
        if (auto el = this->decl_provenance_map.find(decl); el != this->decl_provenance_map.end()) {
            if (auto mpc = this->llvm_prov.find(el->second); mpc != this->llvm_prov.end()) {
                return mpc->second;
            }
        }

        return std::nullopt;
    }

    std::optional< clang::ValueDecl* > ProvenanceInfo::DeclOfAddress(uint64_t target_addr) {
        if (auto el = this->rev_llvm_prov.find(target_addr); el != this->rev_llvm_prov.end()) {
            if (auto mdecl = this->rev_decl_provenance_map.find(el->second);
                mdecl != this->rev_decl_provenance_map.end()) {
                return const_cast< clang::ValueDecl* >(mdecl->second);
            }
        }

        return std::nullopt;
    }

    std::optional< llvm::Value* > ProvenanceInfo::ValueAssociatedWithStatement(
        const clang::Stmt* stmt) const {
        if (auto el = this->stmt_provenance_map.find(stmt); el != this->stmt_provenance_map.end()) {
            return const_cast< llvm::Value* >(el->second);
        }

        return std::nullopt;
    }

    ProvenanceInfo::ProvenanceInfo(
        llvm::DenseMap< const llvm::Value*, uint64_t > llvm_prov,
        llvm::DenseMap< uint64_t, const llvm::Value* > rev_llvm_prov,
        rellic::DecompilationResult::StmtToIRMap stmt_provenance_map,
        rellic::DecompilationResult::IRToStmtMap rev_stmt_provenance_map,
        rellic::DecompilationResult::DeclToIRMap decl_provenance_map,
        rellic::DecompilationResult::IRToDeclMap rev_decl_provenance_map)
        : llvm_prov(std::move(llvm_prov))
        , rev_llvm_prov(std::move(rev_llvm_prov))
        , stmt_provenance_map(std::move(stmt_provenance_map))
        , rev_stmt_provenance_map(std::move(rev_stmt_provenance_map))
        , decl_provenance_map(std::move(decl_provenance_map))
        , rev_decl_provenance_map(std::move(rev_decl_provenance_map)) {}

    FunctionDecompResult ProvenanceInfo::FuncOfAddress(uint64_t target_addr) {
        if (auto decl = this->DeclOfAddress(target_addr)) {
            if (auto el = this->rev_llvm_prov.find(target_addr); el != this->rev_llvm_prov.end()) {
                auto v = el->second;
                if (llvm::Function* func
                    = llvm::dyn_cast< llvm::Function >(const_cast< llvm::Value* >(v))) {
                    if (clang::FunctionDecl* res = clang::dyn_cast< clang::FunctionDecl >(
                            const_cast< clang::ValueDecl* >(*decl))) {
                        return {
                            {func, res, target_addr}
                        };
                    }
                }
            }
        }

        return std::string("Could not find function in rellic prov");
    }
    void SpecDecompilationJob::NameEntity(
        llvm::Constant* v, const anvill::EntityLifter& lifter) const {
        if (auto addr = lifter.AddressOfEntity(v)) {
            if (auto el = this->symbol_map.find(*addr); el != this->symbol_map.end()) {
                v->setName(el->second);
            }
        }
    }

    void SpecDecompilationJob::LiftOrDeclareFunctionsInto(anvill::EntityLifter& lifter) const {
        spec.ForEachFunction([this, lifter](auto decl) {
            llvm::Function* func;
            if (target_funcs.empty() || target_funcs.find(decl->address) != target_funcs.end()) {
                func = lifter.LiftEntity(*decl);
            } else {
                func = lifter.DeclareEntity(*decl);
            }

            this->NameEntity(func, lifter);
            return true;
        });
    }

    void SpecDecompilationJob::LiftOrDeclareVariablesInto(anvill::EntityLifter& lifter) const {
        spec.ForEachVariable([this, &lifter](auto decl) {
            llvm::Constant* cv = lifter.LiftEntity(*decl);

            this->NameEntity(cv, lifter);
            return true;
        });
    }

    std::pair<
        llvm::DenseMap< const llvm::Value*, uint64_t >,
        llvm::DenseMap< uint64_t, const llvm::Value* > >
    SpecDecompilationJob::ExtractLLVMProvenance(const llvm::Module* anvill_mod) const {
        llvm::DenseMap< const llvm::Value*, uint64_t > res;
        llvm::DenseMap< uint64_t, const llvm::Value* > rev;
        for (const llvm::GlobalVariable& var : anvill_mod->globals()) {
            if (auto addr = GetPCMetadata(&var)) {
                res.insert({ &var, *addr });
                rev.insert({ *addr, &var });
            }
        }

        for (const llvm::GlobalAlias& var : anvill_mod->getAliasList()) {
            if (auto addr = GetPCMetadata(&var)) {
                res.insert({ &var, *addr });
                rev.insert({ *addr, &var });
            }
        }

        // Some instructions will not be in the original module due to Rellic
        // changing things around, so try to capture those updates to metadata.
        for (const llvm::Function& func : *anvill_mod) {
            if (auto addr = GetPCMetadata(&func)) {
                res.insert({ &func, *addr });
                rev.insert({ *addr, &func });
            }
            if (!func.isDeclaration()) {
                for (auto& block : func) {
                    for (auto& inst : block) {
                        if (auto addr = GetPCMetadata(&inst)) {
                            res.insert({ &inst, *addr });
                            rev.insert({ *addr, &inst });
                        }
                    }
                }
            }
        }
        return { res, rev };
    }

    void SpecDecompilationJob::CreateSpecLayoutOverride(bool stack_grows_down) const {
        if (args_as_locals) {
            options->additional_variable_providers.push_back(
                std::make_unique< SpecLayoutOverride::Factory >(
                    spec, type_decoder, stack_grows_down));
        }
    }

    DecompilationResult SpecDecompilationJob::PopulateDecompResFromRellic(
        rellic::DecompilationResult res) const {
        std::unordered_map< uint64_t, FunctionDecompResult > function_results;

        auto [prov, rev_prov] = this->ExtractLLVMProvenance(res.module.get());

        ProvenanceInfo prov_info(
            prov, rev_prov, std::move(res.stmt_provenance_map), std::move(res.value_to_stmt_map),
            std::move(res.decl_provenance_map), std::move(res.value_to_decl_map));

        for (auto addr : this->target_funcs) {
            function_results.emplace(addr, prov_info.FuncOfAddress(addr));
        }

        return { context, std::move(res.module), std::move(res.ast), std::move(prov_info),
                 std::move(function_results) };
    }

    CodegenResult SpecDecompilationJob::PopulateCodegenResFromRellic(
        rellic::DecompilationResult res, GvarInfoByBlock gvar_prov) const {
        std::unordered_map< uint64_t, FunctionDecompResult > function_results;

        auto [prov, rev_prov] = this->ExtractLLVMProvenance(res.module.get());

        // NOTE(frabert): we need `value_to_decl_map` later on, so don't `std::move` it
        ProvenanceInfo prov_info(
            prov, rev_prov, std::move(res.stmt_provenance_map), std::move(res.value_to_stmt_map),
            std::move(res.decl_provenance_map), res.value_to_decl_map);

        for (auto addr : this->target_funcs) {
            function_results.emplace(addr, prov_info.FuncOfAddress(addr));
        }

        // Functions may share basic blocks, this map makes sure that a basic block at a specific
        // address only has one resulting LLVM function
        std::unordered_map< std::uint64_t, llvm::Function* > canonical_funcs;
        for (auto& func : res.module->functions()) {
            if (auto addr = anvill::GetBasicBlockAddr(&func)) {
                canonical_funcs[*addr] = &func;
            }
        }

        std::unordered_map< std::uint64_t, clang::CompoundStmt* > blocks;
        for (auto& [addr, func] : canonical_funcs) {
            auto fdecl   = clang::cast< clang::FunctionDecl >(res.value_to_decl_map[func]);
            auto body    = clang::cast< clang::CompoundStmt >(fdecl->getBody());
            blocks[addr] = body;
        }

        return { context,
                 std::move(res.module),
                 std::move(res.ast),
                 std::move(prov_info),
                 std::move(gvar_prov),
                 blocks };
    }

    rellic::Result< DecompilationResult, std::string > SpecDecompilationJob::Decompile() const {
        auto module = std::make_unique< llvm::Module >("lifted_code", *this->context);

        anvill::SpecificationTypeProvider spec_tp(this->spec);
        anvill::SpecificationControlFlowProvider spec_cfp(this->spec);
        anvill::SpecificationMemoryProvider spec_mp(this->spec);

        anvill::LifterOptions options(spec.Arch().get(), *module, spec_tp, spec_cfp, spec_mp);
        options.stack_frame_recovery_options.stack_frame_struct_init_procedure
            = this->stack_initialization_strategy;
        options.should_remove_anvill_pc = this->should_remove_anvill_pc;
        options.pc_metadata_name        = "pc";
        CreateSpecLayoutOverride(options.stack_frame_recovery_options.stack_grows_down);
        anvill::EntityLifter lifter(options);

        this->LiftOrDeclareFunctionsInto(lifter);
        this->LiftOrDeclareVariablesInto(lifter);

        anvill::OptimizeModule(lifter, *module, spec.GetBlockContexts(), spec);

        auto res = rellic::Decompile(std::move(module), std::move(*this->options));

        if (!res.Succeeded()) {
            return res.TakeError().message;
        }

        auto decomp_res = res.TakeValue();

        return this->PopulateDecompResFromRellic(std::move(decomp_res));
    }

    rellic::Result< CodegenResult, std::string > SpecDecompilationJob::DecompileBlocks() const {
        auto module = std::make_unique< llvm::Module >("lifted_code", *this->context);

        anvill::SpecificationTypeProvider spec_tp(this->spec);
        anvill::SpecificationControlFlowProvider spec_cfp(this->spec);
        anvill::SpecificationMemoryProvider spec_mp(this->spec);

        anvill::LifterOptions options(spec.Arch().get(), *module, spec_tp, spec_cfp, spec_mp);
        options.stack_frame_recovery_options.stack_frame_struct_init_procedure
            = this->stack_initialization_strategy;
        options.should_remove_anvill_pc              = this->should_remove_anvill_pc;
        options.pc_metadata_name                     = "pc";
        options.should_remove_assignments_to_next_pc = true;
        CreateSpecLayoutOverride(options.stack_frame_recovery_options.stack_grows_down);
        anvill::EntityLifter lifter(options);

        this->LiftOrDeclareFunctionsInto(lifter);
        this->LiftOrDeclareVariablesInto(lifter);

        anvill::OptimizeModule(lifter, *module, spec.GetBlockContexts(), spec);

        std::unordered_map< uint64_t, std::vector< GlobalVarInfo > > gvars;

        for (auto& func : module->functions()) {
            auto block_addr = anvill::GetBasicBlockAddr(&func);
            if (!block_addr.has_value()) {
                func.deleteBody();
                continue;
            }

            std::vector< GlobalVarInfo > blk_gvars;
            for (auto var : UsedGlobalVars(&func)) {
                auto pc = GetPCMetadata(var);
                if (!pc) {
                    continue;
                }
                auto v = spec.VariableAt(*pc);
                if (v) {
                    size_t sz = v->type->getScalarSizeInBits();
                    blk_gvars.push_back({ std::string(var->getName()), *pc, sz });
                }
                gvars.insert({ *block_addr, blk_gvars });
            }

            // Copy instructions to temporary storage so we don't invalidate iterators
            std::vector< llvm::Instruction* > insts;
            for (auto& inst : llvm::instructions(func)) {
                insts.push_back(&inst);
            }

            for (auto inst : insts) {
                if (auto call = llvm::dyn_cast< llvm::CallInst >(inst)) {
                    auto block_addr = anvill::GetBasicBlockAddr(call->getCalledFunction());
                    if (!block_addr.has_value()) {
                        continue;
                    }
                    call->replaceAllUsesWith(call->getArgOperand(2));
                    call->eraseFromParent();
                }
            }
        }

        rellic::DecompilationOptions dec_opts;
        dec_opts.additional_type_providers = std::move(this->options->additional_type_providers);
        dec_opts.additional_variable_providers
            = std::move(this->options->additional_variable_providers);
        auto maybe_dec_res = rellic::Decompile(std::move(module), std::move(dec_opts));
        if (!maybe_dec_res.Succeeded()) {
            return maybe_dec_res.TakeError().message;
        }

        return PopulateCodegenResFromRellic(maybe_dec_res.TakeValue(), std::move(gvars));
    }

    SpecDecompilationJob::SpecDecompilationJob(SpecDecompilationJobBuilder&& o)
        : context(std::move(o.context))
        , target_funcs(std::move(o.target_funcs))
        , options(std::move(o.options))
        , spec(std::move(o.spec))
        , args_as_locals(o.args_as_locals)
        , type_decoder(o.type_decoder) {
        this->spec.ForEachSymbol([this](uint64_t addr, const std::string& name) {
            this->symbol_map.emplace(addr, name);
            return true;
        });
    }

    rellic::Result< SpecDecompilationJobBuilder, std::string > SpecDecompilationJobBuilder::
        CreateDefaultBuilder(
            const std::string& spec_pb,
            bool propagate_types,
            bool args_as_locals,
            TypeDecoder& type_decoder) {
        std::shared_ptr< llvm::LLVMContext > context = std::make_shared< llvm::LLVMContext >();
#if LLVM_VERSION_NUMBER < LLVM_VERSION(15, 0)
        context.enableOpaquePointers();
#endif

        auto maybe_spec = anvill::Specification::DecodeFromPB(*context, spec_pb);

        if (!maybe_spec.Succeeded()) {
            return { std::string(maybe_spec.TakeError()) };
        }

        auto spec = maybe_spec.TakeValue();

        std::unordered_set< uint64_t > target_function_list;

        spec.ForEachFunction([&](std::shared_ptr< const anvill::FunctionDecl > decl) {
            target_function_list.emplace(decl->address);
            return true;
        });

        auto opts = std::make_unique< rellic::DecompilationOptions >();
        if (propagate_types) {
            opts->additional_type_providers.push_back(
                std::make_unique< SpecTypeProvider::Factory >(spec, type_decoder));
        }
        return SpecDecompilationJobBuilder(
            spec, target_function_list, std::move(opts), args_as_locals, type_decoder,
            std::move(context));
    }

    SpecDecompilationJobBuilder::SpecDecompilationJobBuilder(
        anvill::Specification spec,
        std::unordered_set< uint64_t > target_funcs,
        std::unique_ptr< rellic::DecompilationOptions > options,
        bool args_as_locals,
        TypeDecoder& type_decoder,
        std::shared_ptr< llvm::LLVMContext > context)
        : context(std::move(context))
        , spec(std::move(spec))
        , target_funcs(std::move(target_funcs))
        , options(std::move(options))
        , args_as_locals(args_as_locals)
        , type_decoder(type_decoder) {}

} // namespace irene3
