#pragma once

#include <anvill/Lifters.h>
#include <anvill/Specification.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Stmt.h>
#include <llvm/ADT/DenseMap.h>
#include <llvm/IR/Constant.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/ValueMap.h>
#include <llvm/Support/JSON.h>
#include <memory>
#include <rellic/Decompiler.h>
#include <rellic/Result.h>
#include <stdint.h>
#include <unordered_map>
#include <unordered_set>

namespace irene3
{
    class SpecDecompilationJob;

    // A decompilation job builder allows for configuring a set of default options before
    // constructing a decompilation job.
    class SpecDecompilationJobBuilder {
        friend class SpecDecompilationJob;

      private:
        std::shared_ptr< llvm::LLVMContext > context;
        anvill::Specification spec;

      public:
        // The target function addresses in the binary to decompile, defaults to all functions
        std::unordered_set< uint64_t > target_funcs;

        // The rellic C decompilation options
        std::unique_ptr< rellic::DecompilationOptions > options;

        SpecDecompilationJobBuilder(
            anvill::Specification spec,
            std::unordered_set< uint64_t > target_funcs,
            std::unique_ptr< rellic::DecompilationOptions > options,
            std::shared_ptr< llvm::LLVMContext > context);

        // Attempts to build a SpecDecompilationBuilder from an anvill json specification.
        static rellic::Result< SpecDecompilationJobBuilder, std::string > CreateDefaultBuilder(
            llvm::json::Value spec);
    };

    // A decompiled function
    struct FunctionDecomp {
        llvm::Function* llmv_func;
        clang::FunctionDecl* clang_func;
        uint64_t addr;
    };

    // A decompiled fujnction or an error.
    using FunctionDecompResult = rellic::Result< FunctionDecomp, std::string >;

    // Stores decompilation provenance info, relating C stmts and decls to llvm values and
    // consequently to program counter metadata variables.
    class ProvenanceInfo {
      private:
        llvm::DenseMap< const llvm::Value*, uint64_t > llvm_prov;
        llvm::DenseMap< uint64_t, const llvm::Value* > rev_llvm_prov;

        rellic::DecompilationResult::StmtToIRMap stmt_provenance_map;
        rellic::DecompilationResult::IRToStmtMap rev_stmt_provenance_map;

        rellic::DecompilationResult::DeclToIRMap decl_provenance_map;
        rellic::DecompilationResult::IRToDeclMap rev_decl_provenance_map;

      public:
        ProvenanceInfo(
            llvm::DenseMap< const llvm::Value*, uint64_t > llvm_prov,
            llvm::DenseMap< uint64_t, const llvm::Value* > rev_llvm_prov,
            rellic::DecompilationResult::StmtToIRMap stmt_provenance_map,
            rellic::DecompilationResult::IRToStmtMap rev_stmt_provenance_map,
            rellic::DecompilationResult::DeclToIRMap decl_provenance_map,
            rellic::DecompilationResult::IRToDeclMap rev_decl_provenance_map);

        ProvenanceInfo() = delete;

        // Attempts to find the related address info for a given clang Decl.
        std::optional< uint64_t > AddressOfDecl(const clang::ValueDecl* decl);

        // Attempts to find the clang Decl representing a given address.
        std::optional< clang::ValueDecl* > DeclOfAddress(uint64_t target_addr);

        // Attempts to find the llvm value assosicated with a clang stmt.
        std::optional< llvm::Value* > ValueAssociatedWithStatement(const clang::Stmt* stmt) const;

        // Finds a function decl at the target address.
        FunctionDecompResult FuncOfAddress(uint64_t target_addr);
    };

    struct DecompilationResult {
        std::shared_ptr< llvm::LLVMContext > context;
        std::unique_ptr< llvm::Module > mod;

        std::unique_ptr< clang::ASTUnit > ast;

        ProvenanceInfo prov_info;

        std::unordered_map< uint64_t, FunctionDecompResult > function_results;
    };

    class SpecDecompilationJob {
      private:
        std::shared_ptr< llvm::LLVMContext > context;
        std::unordered_set< uint64_t > target_funcs;
        std::unique_ptr< rellic::DecompilationOptions > options;
        anvill::Specification spec;

        std::unordered_map< uint64_t, std::string > symbol_map;

        void NameEntity(llvm::Constant* v, const anvill::EntityLifter& lifter) const;

        void LiftOrDeclareFunctionsInto(anvill::EntityLifter& lifter) const;
        void LiftOrDeclareVariablesInto(anvill::EntityLifter& lifter) const;

        std::pair<
            llvm::DenseMap< const llvm::Value*, uint64_t >,
            llvm::DenseMap< uint64_t, const llvm::Value* > >
        ExtractLLVMProvenance(const llvm::Module* anvill_mod) const;

        DecompilationResult PopulateDecompResFromRellic(
            std::shared_ptr< llvm::LLVMContext > context, rellic::DecompilationResult res) const;

      public:
        // Gets the underlying anvill spec for this decompilation job.
        const anvill::Specification& GetSpec() const;

        SpecDecompilationJob() = delete;

        // Constructs a decompilation job from a builder.
        SpecDecompilationJob(SpecDecompilationJobBuilder&&);

        // Attempts to decompile the anvill spec to C and LLVM.
        rellic::Result< DecompilationResult, std::string > Decompile() const;
    };
} // namespace irene3
