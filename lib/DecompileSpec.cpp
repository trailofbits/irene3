#include "rellic/Decompiler.h"

#include <anvill/JSON.h>
#include <anvill/Lifters.h>
#include <anvill/Optimize.h>
#include <anvill/Providers.h>
#include <anvill/Specification.h>
#include <clang/AST/Decl.h>
#include <clang/Basic/LLVM.h>
#include <glog/logging.h>
#include <irene3/DecompileSpec.h>
#include <irene3/Util.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/Casting.h>
#include <memory>
#include <optional>
#include <remill/Arch/Arch.h>
#include <remill/BC/Util.h>
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

    DecompilationResult SpecDecompilationJob::PopulateDecompResFromRellic(
        std::shared_ptr< llvm::LLVMContext > context, rellic::DecompilationResult res) const {
        std::unordered_map< uint64_t, FunctionDecompResult > function_results;

        auto [prov, rev_prov] = this->ExtractLLVMProvenance(res.module.get());

        ProvenanceInfo prov_info(
            prov, rev_prov, std::move(res.stmt_provenance_map), std::move(res.value_to_stmt_map),
            std::move(res.decl_provenance_map), std::move(res.value_to_decl_map));

        for (auto addr : this->target_funcs) {
            function_results.emplace(addr, prov_info.FuncOfAddress(addr));
        }

        return { std::move(context), std::move(res.module), std::move(res.ast),
                 std::move(prov_info), std::move(function_results) };
    }

    rellic::Result< DecompilationResult, std::string > SpecDecompilationJob::Decompile() const {
        auto module = std::make_unique< llvm::Module >("lifted_code", *this->context);

        anvill::SpecificationTypeProvider spec_tp(this->spec);
        anvill::SpecificationControlFlowProvider spec_cfp(this->spec);
        anvill::SpecificationMemoryProvider spec_mp(this->spec);

        anvill::LifterOptions options(spec.Arch().get(), *module, spec_tp, spec_cfp, spec_mp);
        options.pc_metadata_name = "pc";
        anvill::EntityLifter lifter(options);

        this->LiftOrDeclareFunctionsInto(lifter);
        this->LiftOrDeclareVariablesInto(lifter);

        anvill::OptimizeModule(lifter, *module);

        auto res = rellic::Decompile(std::move(module), std::move(*this->options));

        if (!res.Succeeded()) {
            return res.TakeError().message;
        }

        auto decomp_res = res.TakeValue();

        return this->PopulateDecompResFromRellic(this->context, std::move(decomp_res));
    }

    SpecDecompilationJob::SpecDecompilationJob(SpecDecompilationJobBuilder&& o)
        : context(std::move(o.context))
        , target_funcs(std::move(o.target_funcs))
        , options(std::move(o.options))
        , spec(std::move(o.spec)) {
        this->spec.ForEachSymbol([this](uint64_t addr, const std::string& name) {
            this->symbol_map.emplace(addr, name);
            return true;
        });
    }

    rellic::Result< SpecDecompilationJobBuilder, std::string > SpecDecompilationJobBuilder::
        CreateDefaultBuilder(llvm::json::Value spec_json) {
        std::shared_ptr< llvm::LLVMContext > context = std::make_shared< llvm::LLVMContext >();
        context->enableOpaquePointers();

        auto maybe_spec = anvill::Specification::DecodeFromJSON(*context, spec_json);

        if (!maybe_spec.Succeeded()) {
            return { std::string(maybe_spec.TakeError().message) };
        }

        auto spec = maybe_spec.TakeValue();

        std::unordered_set< uint64_t > target_function_list;

        spec.ForEachFunction([&](std::shared_ptr< const anvill::FunctionDecl > decl) {
            target_function_list.emplace(decl->address);
            return true;
        });

        auto opts = std::make_unique< rellic::DecompilationOptions >();
        return SpecDecompilationJobBuilder(
            spec, target_function_list, std::move(opts), std::move(context));
    }

    SpecDecompilationJobBuilder::SpecDecompilationJobBuilder(
        anvill::Specification spec,
        std::unordered_set< uint64_t > target_funcs,
        std::unique_ptr< rellic::DecompilationOptions > options,
        std::shared_ptr< llvm::LLVMContext > context)
        : context(std::move(context))
        , spec(std::move(spec))
        , target_funcs(std::move(target_funcs))
        , options(std::move(options)) {}

} // namespace irene3
