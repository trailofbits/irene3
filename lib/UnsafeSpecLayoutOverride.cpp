/*
 * Copyright (c) 2023-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "SpecLayoutOverride.h"

#include <algorithm>
#include <anvill/Declarations.h>
#include <anvill/Specification.h>
#include <anvill/Utils.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Type.h>
#include <functional>
#include <glog/logging.h>
#include <irene3/Util.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/Support/raw_ostream.h>
#include <optional>
#include <rellic/AST/DecompilationContext.h>
#include <rellic/AST/FunctionLayoutOverride.h>
#include <remill/Arch/Arch.h>
#include <remill/BC/ABI.h>
#include <string>
#include <tuple>
#include <utility>

namespace irene3
{
    using namespace rellic;
    struct UnsafeSpecLayoutOverride::Impl {
        DecompilationContext& ctx;
        anvill::Specification spec;
        TypeDecoder& type_decoder;
        bool stack_grows_down;
        bool should_preserve_unused_decls;

        Impl(
            DecompilationContext& ctx,
            anvill::Specification& spec,
            TypeDecoder& type_decoder,
            bool should_preserve_unused_decls)
            : ctx(ctx)
            , spec(spec)
            , type_decoder(type_decoder)
            , should_preserve_unused_decls(should_preserve_unused_decls) {}

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

        std::vector< clang::ParmVarDecl* > CreateFunctionParams(
            llvm::Function& func, unsigned first_var_idx) {
            std::vector< clang::ParmVarDecl* > params;
            for (auto& arg : func.args()) {
                if (arg.getArgNo() >= first_var_idx) {
                    continue;
                }
                auto& parm = ctx.value_decls[&arg];
                if (parm) {
                    continue;
                }
                // Create a name
                auto name
                    = arg.hasName() ? arg.getName().str() : "arg" + std::to_string(arg.getArgNo());
                // Get parent function declaration
                auto func    = arg.getParent();
                auto fdecl   = clang::cast< clang::FunctionDecl >(ctx.value_decls[func]);
                auto argtype = ctx.type_provider->GetArgumentType(arg);
                // Create a declaration
                parm = ctx.ast.CreateParamDecl(fdecl, argtype, name);
                params.push_back(clang::dyn_cast< clang::ParmVarDecl >(ctx.value_decls[&arg]));
            }
            return params;
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
                if (arg.getArgNo() >= first_var_idx) {
                    continue;
                }
                // Keep arguments before the first local as real arguments
                arg_types.push_back(ctx.type_provider->GetArgumentType(arg));
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
            auto fspec = spec.FunctionAt(maybe_block_ctx->get().GetParentFunctionAddress());
            auto available_vars     = block_ctx.LiveParamsAtEntryAndExit();
            auto num_available_vars = available_vars.size();

            auto first_var_idx = func.arg_size() - num_available_vars;

            fdecl->setParams(CreateFunctionParams(func, first_var_idx));

            for (unsigned i = 0; i < num_available_vars; ++i) {
                auto arg = func.getArg(i);
                auto var = available_vars[i];
                if (arg->getNumUses() != 0 || should_preserve_unused_decls) {
                    auto& decl = ctx.value_decls[arg];
                    auto vdecl = ctx.ast.CreateVarDecl(
                        fdecl, type_decoder.Decode(ctx, spec, var.param.spec_type, arg->getType()),
                        arg->getName().str());
                    decl = vdecl;
                    fdecl->addDecl(vdecl);
                }
            }
        }

        bool VisitInstruction(
            llvm::Instruction& insn, clang::FunctionDecl* fdecl, clang::ValueDecl*& vdecl) {
            return false;
        }

        bool NeedsDereference(llvm::Function& func, llvm::Value& value) {
            if (llvm::isa< llvm::AllocaInst >(value)) {
                return true;
            }
            auto block_addr = anvill::GetBasicBlockAddr(&func);
            if (!block_addr.has_value()) {
                return false;
            }
            auto block_contexts  = spec.GetBlockContexts();
            auto maybe_block_ctx = block_contexts.GetBasicBlockContextForAddr(*block_addr);
            CHECK(maybe_block_ctx.has_value());
            const anvill::BasicBlockContext& block_ctx = maybe_block_ctx.value();
            auto fspec = spec.FunctionAt(maybe_block_ctx->get().GetParentFunctionAddress());
            auto available_vars     = block_ctx.LiveParamsAtEntryAndExit();
            auto num_available_vars = available_vars.size();
            auto first_var_idx      = func.arg_size() - num_available_vars;
            auto arg                = llvm::dyn_cast< llvm::Argument >(&value);
            return arg && arg->getArgNo() >= first_var_idx;
        }
    };

    UnsafeSpecLayoutOverride::UnsafeSpecLayoutOverride(
        DecompilationContext& dec_ctx,
        anvill::Specification& spec,
        TypeDecoder& type_decoder,
        bool should_preserve_unused_decls)
        : FunctionLayoutOverride(dec_ctx)
        , impl(
              std::make_unique< Impl >(dec_ctx, spec, type_decoder, should_preserve_unused_decls)) {
    }
    UnsafeSpecLayoutOverride::~UnsafeSpecLayoutOverride() = default;

    bool UnsafeSpecLayoutOverride::HasOverride(llvm::Function& func) {
        return impl->HasOverride(func);
    }

    std::vector< clang::QualType > UnsafeSpecLayoutOverride::GetArguments(llvm::Function& func) {
        return impl->GetArguments(func);
    }

    void UnsafeSpecLayoutOverride::BeginFunctionVisit(
        llvm::Function& func, clang::FunctionDecl* fdecl) {
        impl->BeginFunctionVisit(func, fdecl);
    }

    bool UnsafeSpecLayoutOverride::VisitInstruction(
        llvm::Instruction& insn, clang::FunctionDecl* fdecl, clang::ValueDecl*& vdecl) {
        return impl->VisitInstruction(insn, fdecl, vdecl);
    }

    bool UnsafeSpecLayoutOverride::NeedsDereference(llvm::Function& func, llvm::Value& val) {
        return impl->NeedsDereference(func, val);
    }

    UnsafeSpecLayoutOverride::Factory::Factory(
        anvill::Specification spec, TypeDecoder& type_decoder)
        : spec(spec)
        , type_decoder(type_decoder) {}

    std::unique_ptr< FunctionLayoutOverride > UnsafeSpecLayoutOverride::Factory::create(
        rellic::DecompilationContext& dec_ctx) {
        return std::make_unique< UnsafeSpecLayoutOverride >(dec_ctx, spec, type_decoder, false);
    }
} // namespace irene3