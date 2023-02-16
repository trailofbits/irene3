#pragma once

#include <anvill/Lifters.h>
#include <anvill/Specification.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Stmt.h>
#include <cstdint>
#include <irene3/TypeDecoder.h>
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
#include <vector>

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

        // Whether arguments that represent stack locations should be treated as locals by Rellic
        bool args_as_locals;

        // Whether arguments that represent stack locations should be represented as separate locals
        // or not
        bool unsafe_stack_locations;

        // Type decoder to be used by Rellic when generating locals
        TypeDecoder& type_decoder;

        inline const anvill::Specification& GetSpec() const { return spec; }

        SpecDecompilationJobBuilder(
            anvill::Specification spec,
            std::unordered_set< uint64_t > target_funcs,
            std::unique_ptr< rellic::DecompilationOptions > options,
            bool args_as_locals,
            bool unsafe_stack_locations,
            TypeDecoder& type_decoder,
            std::shared_ptr< llvm::LLVMContext > context);

        // Attempts to build a SpecDecompilationBuilder from an anvill json specification.
        static rellic::Result< SpecDecompilationJobBuilder, std::string > CreateDefaultBuilder(
            const std::string& spec_pb,
            bool propagate_types,
            bool args_as_locals,
            bool unsafe_stack_locations,
            TypeDecoder& type_decoder);
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

    struct GlobalVarInfo {
        std::string name;
        uint64_t address;
        size_t size;
    };

    using GvarInfoByBlock = std::unordered_map< std::uint64_t, std::vector< GlobalVarInfo > >;

    struct CodegenResult {
        std::shared_ptr< llvm::LLVMContext > context;
        std::unique_ptr< llvm::Module > mod;

        std::unique_ptr< clang::ASTUnit > ast;

        ProvenanceInfo prov_info;

        GvarInfoByBlock block_globals;

        std::unordered_map< std::uint64_t, clang::CompoundStmt* > blocks;
    };

    class SpecDecompilationJob {
      public:
        anvill::StackFrameStructureInitializationProcedure stack_initialization_strategy
            = anvill::StackFrameStructureInitializationProcedure::kSymbolic;
        bool should_remove_anvill_pc = true;

      private:
        std::shared_ptr< llvm::LLVMContext > context;
        std::unordered_set< uint64_t > target_funcs;
        std::unique_ptr< rellic::DecompilationOptions > options;
        anvill::Specification spec;
        bool args_as_locals;
        bool unsafe_stack_locations;
        TypeDecoder& type_decoder;

        std::unordered_map< uint64_t, std::string > symbol_map;

        void NameEntity(llvm::Constant* v, const anvill::EntityLifter& lifter) const;

        void LiftOrDeclareFunctionsInto(anvill::EntityLifter& lifter) const;
        void LiftOrDeclareVariablesInto(anvill::EntityLifter& lifter) const;

        std::pair<
            llvm::DenseMap< const llvm::Value*, uint64_t >,
            llvm::DenseMap< uint64_t, const llvm::Value* > >
        ExtractLLVMProvenance(const llvm::Module* anvill_mod) const;

        DecompilationResult PopulateDecompResFromRellic(rellic::DecompilationResult res) const;
        CodegenResult PopulateCodegenResFromRellic(
            rellic::DecompilationResult res, GvarInfoByBlock) const;
        void CreateSpecLayoutOverride(bool stack_grows_down) const;

      public:
        // Gets the underlying anvill spec for this decompilation job.
        const anvill::Specification& GetSpec() const;

        SpecDecompilationJob() = delete;

        // Constructs a decompilation job from a builder.
        SpecDecompilationJob(SpecDecompilationJobBuilder&&);

        rellic::Result< CodegenResult, std::string > DecompileBlocks() const;

        // Attempts to decompile the anvill spec to C and LLVM.
        rellic::Result< DecompilationResult, std::string > Decompile() const;
    };
} // namespace irene3
