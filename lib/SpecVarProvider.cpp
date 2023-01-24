/*
 * Copyright (c) 2023-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "SpecVarProvider.h"

#include "anvill/Declarations.h"
#include "anvill/Utils.h"

#include <anvill/Specification.h>
#include <clang/AST/Type.h>
#include <functional>
#include <irene3/Util.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/Support/raw_ostream.h>
#include <optional>
#include <rellic/AST/DecompilationContext.h>
#include <rellic/AST/FunctionLayoutOverride.h>
#include <string>

namespace irene3
{
    using namespace rellic;
    struct SpecVarProvider::Impl {
        DecompilationContext& ctx;
        anvill::Specification spec;
        TypeDecoder& type_decoder;

        Impl(DecompilationContext& ctx, anvill::Specification& spec, TypeDecoder& type_decoder)
            : ctx(ctx)
            , spec(spec)
            , type_decoder(type_decoder) {}

        std::optional< std::reference_wrapper< const anvill::BasicBlockContext > > GetContext(
            llvm::Function& func) {
            auto block_addr = anvill::GetBasicBlockAddr(&func);
            if (!block_addr.has_value()) {
                return std::nullopt;
            }

            auto block_contexts = spec.GetBlockContexts();
            return block_contexts.GetBasicBlockContextForAddr(*block_addr);
        }

        bool HasOverride(llvm::Function& func) {
            auto block_addr = anvill::GetBasicBlockAddr(&func);
            if (!block_addr.has_value()) {
                return false;
            }

            auto block_contexts = spec.GetBlockContexts();
            return block_contexts.GetBasicBlockContextForAddr(*block_addr).has_value();
        }

        std::vector< clang::QualType > GetArguments(llvm::Function& func) {
            auto block_addr = anvill::GetBasicBlockAddr(&func);
            CHECK(block_addr.has_value());
            auto block_contexts  = spec.GetBlockContexts();
            auto maybe_block_ctx = block_contexts.GetBasicBlockContextForAddr(*block_addr);
            CHECK(maybe_block_ctx.has_value());
            const anvill::BasicBlockContext& block_ctx = maybe_block_ctx.value();
            auto available_vars                        = block_ctx.LiveParamsAtEntryAndExit();
            auto num_available_vars                    = available_vars.size();

            auto first_var_idx = func.arg_size() - num_available_vars;

            std::vector< clang::QualType > arg_types;
            for (auto& arg : func.args()) {
                if (arg.getArgNo() < first_var_idx) {
                    // Keep arguments before the first local as real arguments
                    arg_types.push_back(ctx.type_provider->GetArgumentType(arg));
                }
            }

            return arg_types;
        }

        void BeginFunctionVisit(llvm::Function& func, clang::FunctionDecl* fdecl) {
            auto block_addr = anvill::GetBasicBlockAddr(&func);
            CHECK(block_addr.has_value());
            auto block_contexts  = spec.GetBlockContexts();
            auto maybe_block_ctx = block_contexts.GetBasicBlockContextForAddr(*block_addr);
            CHECK(maybe_block_ctx.has_value());
            const anvill::BasicBlockContext& block_ctx = maybe_block_ctx.value();
            auto fspec                                 = spec.FunctionAt(*block_addr);
            auto available_vars                        = block_ctx.LiveParamsAtEntryAndExit();
            auto num_available_vars                    = available_vars.size();

            auto first_var_idx = func.arg_size() - num_available_vars;

            std::vector< clang::ParmVarDecl* > params;
            for (auto& arg : func.args()) {
                if (arg.getArgNo() >= first_var_idx) {
                    continue;
                }
                auto& parm{ ctx.value_decls[&arg] };
                if (parm) {
                    continue;
                }
                // Create a name
                auto name{ arg.hasName() ? arg.getName().str()
                                         : "arg" + std::to_string(arg.getArgNo()) };
                // Get parent function declaration
                auto func{ arg.getParent() };
                auto fdecl{ clang::cast< clang::FunctionDecl >(ctx.value_decls[func]) };
                auto argtype = ctx.type_provider->GetArgumentType(arg);
                // Create a declaration
                parm = ctx.ast.CreateParamDecl(fdecl, argtype, name);
                params.push_back(clang::dyn_cast< clang::ParmVarDecl >(ctx.value_decls[&arg]));
            }
            fdecl->setParams(params);

            if (fspec->stack_depth == 0) {
                return;
            }

            auto locals_struct = ctx.ast.CreateStructDecl(fdecl, "locals");
            locals_struct->completeDefinition();

            fdecl->addDecl(locals_struct);

            auto stack_union = ctx.ast.CreateUnionDecl(fdecl, "stack");
            auto raw_stack   = ctx.ast.CreateFieldDecl(
                  stack_union,
                  ctx.ast_ctx.getConstantArrayType(
                      ctx.ast_ctx.CharTy, llvm::APInt(64, fspec->stack_depth), nullptr,
                      clang::ArrayType::ArraySizeModifier::Normal, 0),
                  "raw");
            stack_union->addDecl(raw_stack);

            stack_union->addDecl(ctx.ast.CreateFieldDecl(
                stack_union, ctx.ast_ctx.getRecordType(locals_struct), "locals"));
            stack_union->completeDefinition();
            fdecl->addDecl(stack_union);
            fdecl->addDecl(
                ctx.ast.CreateVarDecl(fdecl, ctx.ast_ctx.getRecordType(stack_union), "stack"));

            // TODO(frabert): put stack variables into `locals_struct`, convert argument refs into
            // field refs
        }

        bool VisitInstruction(
            llvm::Instruction& insn, clang::FunctionDecl* fdecl, clang::ValueDecl*& vdecl) {
            return false;
        }
    };

    SpecVarProvider::SpecVarProvider(
        DecompilationContext& dec_ctx, anvill::Specification& spec, TypeDecoder& type_decoder)
        : FunctionLayoutOverride(dec_ctx)
        , impl(std::make_unique< Impl >(dec_ctx, spec, type_decoder)) {}
    SpecVarProvider::~SpecVarProvider() = default;

    bool SpecVarProvider::HasOverride(llvm::Function& func) { return impl->HasOverride(func); }

    std::vector< clang::QualType > SpecVarProvider::GetArguments(llvm::Function& func) {
        return impl->GetArguments(func);
    }

    void SpecVarProvider::BeginFunctionVisit(llvm::Function& func, clang::FunctionDecl* fdecl) {
        impl->BeginFunctionVisit(func, fdecl);
    }

    bool SpecVarProvider::VisitInstruction(
        llvm::Instruction& insn, clang::FunctionDecl* fdecl, clang::ValueDecl*& vdecl) {
        return impl->VisitInstruction(insn, fdecl, vdecl);
    }

    SpecVarProvider::Factory::Factory(anvill::Specification spec, TypeDecoder& type_decoder)
        : spec(spec)
        , type_decoder(type_decoder) {}

    std::unique_ptr< FunctionLayoutOverride > SpecVarProvider::Factory::create(
        rellic::DecompilationContext& dec_ctx) {
        return std::make_unique< SpecVarProvider >(dec_ctx, spec, type_decoder);
    }
} // namespace irene3