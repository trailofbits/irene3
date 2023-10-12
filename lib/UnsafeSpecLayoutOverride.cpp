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
#include <llvm/IR/Argument.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/Support/raw_ostream.h>
#include <optional>
#include <rellic/AST/DecompilationContext.h>
#include <rellic/AST/FunctionLayoutOverride.h>
#include <remill/Arch/Arch.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Util.h>
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
        const std::unordered_set< std::string >& required_globals;

        Impl(
            DecompilationContext& ctx,
            anvill::Specification& spec,
            TypeDecoder& type_decoder,
            bool should_preserve_unused_decls,
            const std::unordered_set< std::string >& required_globals)
            : ctx(ctx)
            , spec(spec)
            , type_decoder(type_decoder)
            , should_preserve_unused_decls(should_preserve_unused_decls)
            , required_globals(required_globals) {}

        std::optional< std::reference_wrapper< const anvill::BasicBlockContext > > GetContext(
            llvm::Function& func) {
            auto block_uid = anvill::GetBasicBlockUid(&func);
            if (!block_uid.has_value()) {
                return std::nullopt;
            }

            auto block_contexts = spec.GetBlockContexts();
            return block_contexts.GetBasicBlockContextForUid(*block_uid);
        }

        bool HasOverride(llvm::Function& func) {
            auto block_uid = anvill::GetBasicBlockUid(&func);
            if (!block_uid.has_value()) {
                return false;
            }

            auto block_contexts = spec.GetBlockContexts();
            return block_contexts.GetBasicBlockContextForUid(*block_uid).has_value();
        }

        clang::QualType CreateCharArray(unsigned size) {
            return ctx.ast_ctx.getConstantArrayType(
                ctx.ast_ctx.CharTy, llvm::APInt(64, size), nullptr,
                clang::ArrayType::ArraySizeModifier::Normal, 0);
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
            auto block_uid = anvill::GetBasicBlockUid(&func);
            CHECK(block_uid.has_value());
            auto block_contexts  = spec.GetBlockContexts();
            auto maybe_block_ctx = block_contexts.GetBasicBlockContextForUid(*block_uid);
            CHECK(maybe_block_ctx.has_value());
            // const anvill::BasicBlockContext& block_ctx = maybe_block_ctx.value();
            auto fspec = spec.FunctionAt(maybe_block_ctx->get().GetParentFunctionAddress());

            auto available_vars     = fspec->in_scope_variables;
            auto num_available_vars = available_vars.size();

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

        void DeclUsedGlobals(
            llvm::Function& func, clang::FunctionDecl* fdecl, anvill::Specification& spec) {
            auto vars = UsedGlobalValue< llvm::GlobalVariable >(&func, required_globals);
            for (auto gv : vars) {
                auto maybe_addr = GetPCMetadata(gv);
                if (!maybe_addr) {
                    continue;
                }

                auto var = spec.VariableAt(*maybe_addr);
                auto type
                    = type_decoder.Decode(ctx, spec, var->spec_type, gv->getValueType(), false);
                if (!type.isNull()) {
                    auto& decl = ctx.value_decls[gv];
                    auto name  = std::string(gv->getName());
                    decl       = ctx.ast.CreateVarDecl(fdecl, type, name);
                    fdecl->addDecl(decl);
                }
            }
        }

        void DeclUsedFunctions(
            llvm::Function& func, clang::FunctionDecl* fdecl, anvill::Specification& spec) {
            auto vars = UsedGlobalValue< llvm::Function >(&func, required_globals);
            for (auto gv : vars) {
                if (anvill::GetBasicBlockUid(gv)) {
                    continue;
                }

                auto maybe_addr = GetPCMetadata(gv);
                if (!maybe_addr) {
                    LOG(ERROR) << "no pc metadata for " << std::string(gv->getName());
                    continue;
                }

                auto var = spec.FunctionAt(*maybe_addr);

                auto ftype = std::make_shared< anvill::FunctionType >();
                for (auto param : var->params) {
                    ftype->arguments.push_back(param.spec_type);
                }
                ftype->return_type = var->returns.spec_type;
                ftype->is_variadic = var->is_variadic;

                auto type = type_decoder.Decode(ctx, spec, ftype, gv->getValueType(), true);
                if (!type.isNull()) {
                    auto new_fdecl
                        = ctx.ast.CreateFunctionDecl(fdecl, type, std::string(gv->getName()));

                    size_t i = 0;
                    std::vector< clang::ParmVarDecl* > parms;
                    for (auto param : var->params) {
                        ftype->arguments.push_back(param.spec_type);
                        parms.push_back(ctx.ast.CreateParamDecl(
                            new_fdecl,
                            type_decoder.Decode(
                                ctx, spec, param.spec_type, gv->getFunctionType()->getParamType(i),
                                true),
                            param.name));

                        i++;
                    }
                    new_fdecl->setParams(parms);

                    auto& decl = ctx.value_decls[gv];
                    auto name  = std::string(gv->getName());

                    decl = new_fdecl;
                    fdecl->addDecl(decl);
                }
            }
        }

        void BeginFunctionVisit(llvm::Function& func, clang::FunctionDecl* fdecl) {
            auto block_uid = anvill::GetBasicBlockUid(&func);
            CHECK(block_uid.has_value());
            auto block_contexts  = spec.GetBlockContexts();
            auto maybe_block_ctx = block_contexts.GetBasicBlockContextForUid(*block_uid);
            CHECK(maybe_block_ctx.has_value());
            // const anvill::BasicBlockContext& block_ctx = maybe_block_ctx.value();
            auto fspec = spec.FunctionAt(maybe_block_ctx->get().GetParentFunctionAddress());
            this->DeclUsedGlobals(func, fdecl, spec);
            this->DeclUsedFunctions(func, fdecl, spec);
            auto available_vars     = fspec->in_scope_variables;
            auto num_available_vars = fspec->in_scope_variables.size();

            auto first_var_idx = func.arg_size() - num_available_vars;

            fdecl->setParams(CreateFunctionParams(func, first_var_idx));

            auto add_arg_to_local_override
                = [fdecl, this](llvm::Argument* arg, clang::QualType ty) {
                      if (arg->getNumUses() != 0 || this->should_preserve_unused_decls) {
                          auto& decl = this->ctx.value_decls[arg];
                          auto vdecl = this->ctx.ast.CreateVarDecl(fdecl, ty, arg->getName().str());
                          decl       = vdecl;
                          fdecl->addDecl(decl);
                      }
                  };

            // Setup the stack variable as well
            add_arg_to_local_override(
                func.getArg(remill::kStatePointerArgNum),
                this->CreateCharArray(fspec->maximum_depth));

            for (unsigned i = 0; i < num_available_vars; ++i) {
                auto arg = func.getArg(i + first_var_idx);
                auto var = available_vars[i];
                auto ty  = type_decoder.Decode(ctx, spec, var.spec_type, var.type, false);

                LOG_IF(ERROR, ty.isNull()) << "Expected to be able to decode type for param "
                                           << var.name << " in " << std::string(func.getName());
                if (!ty.isNull()) {
                    add_arg_to_local_override(arg, ty);
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
            auto block_uid = anvill::GetBasicBlockUid(&func);
            if (!block_uid.has_value()) {
                return false;
            }
            auto block_contexts  = spec.GetBlockContexts();
            auto maybe_block_ctx = block_contexts.GetBasicBlockContextForUid(*block_uid);
            CHECK(maybe_block_ctx.has_value());
            auto fspec = spec.FunctionAt(maybe_block_ctx->get().GetParentFunctionAddress());
            const auto& available_vars = fspec->in_scope_variables;
            auto num_available_vars    = available_vars.size();
            auto first_var_idx         = func.arg_size() - num_available_vars;
            auto arg                   = llvm::dyn_cast< llvm::Argument >(&value);
            if (arg && arg->getArgNo() >= first_var_idx) {
                auto decl = this->ctx.value_decls[arg];
                // Ghidra considers array arguments as passed by value
                return !decl->getType()->isArrayType();
            }
            return arg && arg->getArgNo() == remill::kStatePointerArgNum;
        }
    };

    UnsafeSpecLayoutOverride::UnsafeSpecLayoutOverride(
        DecompilationContext& dec_ctx,
        anvill::Specification& spec,
        TypeDecoder& type_decoder,
        bool should_preserve_unused_decls,
        const std::unordered_set< std::string >& required_globals)
        : FunctionLayoutOverride(dec_ctx)
        , impl(std::make_unique< Impl >(
              dec_ctx, spec, type_decoder, should_preserve_unused_decls, required_globals)) {}
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
        anvill::Specification spec,
        TypeDecoder& type_decoder,
        const std::unordered_set< std::string >& required_globals)
        : spec(spec)
        , type_decoder(type_decoder)
        , required_globals(required_globals) {}

    std::unique_ptr< FunctionLayoutOverride > UnsafeSpecLayoutOverride::Factory::create(
        rellic::DecompilationContext& dec_ctx) {
        return std::make_unique< UnsafeSpecLayoutOverride >(
            dec_ctx, spec, type_decoder, false, required_globals);
    }
} // namespace irene3
