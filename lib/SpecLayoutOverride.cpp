/*
 * Copyright (c) 2023-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "SpecLayoutOverride.h"

#include <anvill/Declarations.h>
#include <anvill/Specification.h>
#include <anvill/Utils.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Type.h>
#include <functional>
#include <irene3/Util.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/Support/raw_ostream.h>
#include <optional>
#include <rellic/AST/DecompilationContext.h>
#include <rellic/AST/FunctionLayoutOverride.h>
#include <remill/BC/ABI.h>
#include <string>
#include <tuple>
#include <utility>

namespace irene3
{
    using namespace rellic;
    struct SpecLayoutOverride::Impl {
        DecompilationContext& ctx;
        anvill::Specification spec;
        TypeDecoder& type_decoder;
        bool stack_grows_down;

        Impl(
            DecompilationContext& ctx,
            anvill::Specification& spec,
            TypeDecoder& type_decoder,
            bool stack_grows_down)
            : ctx(ctx)
            , spec(spec)
            , type_decoder(type_decoder)
            , stack_grows_down(stack_grows_down) {}

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
                if (arg.getArgNo() == remill::kStatePointerArgNum) {
                    // The state pointer is actually the stack, and is treated separately
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
                if (arg.getArgNo() == remill::kStatePointerArgNum) {
                    continue;
                }
                // Keep arguments before the first local as real arguments
                arg_types.push_back(ctx.type_provider->GetArgumentType(arg));
            }

            return arg_types;
        }

        clang::QualType CreateCharArray(unsigned size) {
            return ctx.ast_ctx.getConstantArrayType(
                ctx.ast_ctx.CharTy, llvm::APInt(64, size), nullptr,
                clang::ArrayType::ArraySizeModifier::Normal, 0);
        }

        void CreatePadding(clang::RecordDecl* strct, unsigned amount, std::string name) {
            auto padding_ty    = CreateCharArray(amount);
            auto padding_field = ctx.ast.CreateFieldDecl(strct, padding_ty, name);
            strct->addDecl(padding_field);
        }

        void PopulateStackStruct(
            llvm::Function& func,
            clang::FunctionDecl* fdecl,
            const std::vector< anvill::BasicBlockVariable >& available_vars,
            unsigned first_var_idx,
            const remill::Register* stack_pointer_reg,
            anvill::AbstractStack& stk,
            clang::RecordDecl* locals_struct,
            clang::VarDecl* stack_var,
            clang::FieldDecl* locals_field) {
            unsigned num_available_vars = available_vars.size();
            std::vector< std::pair< llvm::Argument*, unsigned > > stack_vars;

            for (size_t i = 0; i < num_available_vars; ++i) {
                auto arg   = func.getArg(i + first_var_idx);
                auto& var  = available_vars[i];
                if (var.param.mem_reg == stack_pointer_reg) {
                    auto offset = stk.StackOffsetFromStackPointer(var.param.mem_offset);
                    // A declared local *must* be contained in the stack
                    CHECK(offset.has_value());
                    stack_vars.push_back({ arg, *offset });
                } else {
                    auto type = type_decoder.Decode(ctx, spec, var.param.spec_type, arg->getType());
                    auto& decl = ctx.value_decls[arg];
                    auto name  = arg->getName().str();
                    decl       = ctx.ast.CreateVarDecl(fdecl, type, name);
                    fdecl->addDecl(decl);
                }
            }

            // Sort stack variables in order of increasing offset
            std::sort(stack_vars.begin(), stack_vars.end(), [&](auto a, auto b) {
                return a.second < b.second;
            });

            unsigned current_offset = 0;
            unsigned num_paddings   = 0;
            // FIXME(frabert): this code ignores the fact that types have a natural alignment
            for (auto [var, var_offset] : stack_vars) {
                auto& var_spec = available_vars[var->getArgNo() - first_var_idx];
                auto type
                    = type_decoder.Decode(ctx, spec, var_spec.param.spec_type, var->getType());
                auto& decl = ctx.value_decls[var];
                auto name  = stack_var->getName().str();

                if (var_offset > current_offset) {
                    CreatePadding(
                        locals_struct, var_offset - current_offset,
                        "padding_" + std::to_string(num_paddings++));
                    current_offset = var_offset;
                }

                auto field_decl = ctx.ast.CreateFieldDecl(locals_struct, type, name);
                locals_struct->addDecl(field_decl);

                auto base_stack  = ctx.ast.CreateDeclRef(stack_var);
                auto base_locals = ctx.ast.CreateFieldAcc(base_stack, locals_field, false);
                auto local_var
                    = ctx.ast.CreateVarDecl(fdecl, ctx.ast_ctx.getPointerType(type), name);
                local_var->setInit(
                    ctx.ast.CreateAddrOf(ctx.ast.CreateFieldAcc(base_locals, field_decl, false)));
                decl = local_var;
                fdecl->addDecl(local_var);
                current_offset += ctx.ast_ctx.getTypeSize(type) / 8;
            }
        }

        std::tuple<
            clang::RecordDecl*,
            clang::RecordDecl*,
            clang::FieldDecl*,
            clang::VarDecl*,
            clang::VarDecl* >
        CreateStackLayout(clang::FunctionDecl* fdecl, const anvill::FunctionDecl& fspec) {
            auto locals_struct = ctx.ast.CreateStructDecl(fdecl, "locals_struct");

            fdecl->addDecl(locals_struct);

            auto stack_union = ctx.ast.CreateUnionDecl(fdecl, "stack_union");
            auto raw_stack_field
                = ctx.ast.CreateFieldDecl(stack_union, CreateCharArray(fspec.stack_depth), "raw");
            stack_union->addDecl(raw_stack_field);

            auto locals_field = ctx.ast.CreateFieldDecl(
                stack_union, ctx.ast_ctx.getRecordType(locals_struct), "locals");
            stack_union->addDecl(locals_field);
            fdecl->addDecl(stack_union);
            auto stack_var
                = ctx.ast.CreateVarDecl(fdecl, ctx.ast_ctx.getRecordType(stack_union), "stack");
            fdecl->addDecl(stack_var);

            auto raw_stack_var = ctx.ast.CreateVarDecl(fdecl, ctx.ast_ctx.VoidPtrTy, "raw_stack");
            raw_stack_var->setInit(
                ctx.ast.CreateFieldAcc(ctx.ast.CreateDeclRef(stack_var), raw_stack_field, false));
            fdecl->addDecl(raw_stack_var);

            return { locals_struct, stack_union, locals_field, stack_var, raw_stack_var };
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
            auto stack_pointer_reg
                = spec.Arch()->RegisterByName(spec.Arch()->StackPointerRegisterName());
            auto stack_arg = func.getArg(remill::kStatePointerArgNum);

            auto first_var_idx = func.arg_size() - num_available_vars;

            fdecl->setParams(CreateFunctionParams(func, first_var_idx));

            auto [locals_struct, stack_union, locals_field, stack_var, raw_stack_var]
                = CreateStackLayout(fdecl, *fspec);

            ctx.value_decls[stack_arg] = raw_stack_var;

            anvill::AbstractStack stk(
                func.getContext(),
                {
                    {block_ctx.GetStackSize(), stack_arg}
            },
                stack_grows_down, block_ctx.GetPointerDisplacement());

            PopulateStackStruct(
                func, fdecl, available_vars, first_var_idx, stack_pointer_reg, stk, locals_struct,
                stack_var, locals_field);
            locals_struct->completeDefinition();
            stack_union->completeDefinition();
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

    SpecLayoutOverride::SpecLayoutOverride(
        DecompilationContext& dec_ctx,
        anvill::Specification& spec,
        TypeDecoder& type_decoder,
        bool stack_grows_down)
        : FunctionLayoutOverride(dec_ctx)
        , impl(std::make_unique< Impl >(dec_ctx, spec, type_decoder, stack_grows_down)) {}
    SpecLayoutOverride::~SpecLayoutOverride() = default;

    bool SpecLayoutOverride::HasOverride(llvm::Function& func) { return impl->HasOverride(func); }

    std::vector< clang::QualType > SpecLayoutOverride::GetArguments(llvm::Function& func) {
        return impl->GetArguments(func);
    }

    void SpecLayoutOverride::BeginFunctionVisit(llvm::Function& func, clang::FunctionDecl* fdecl) {
        impl->BeginFunctionVisit(func, fdecl);
    }

    bool SpecLayoutOverride::VisitInstruction(
        llvm::Instruction& insn, clang::FunctionDecl* fdecl, clang::ValueDecl*& vdecl) {
        return impl->VisitInstruction(insn, fdecl, vdecl);
    }

    bool SpecLayoutOverride::NeedsDereference(llvm::Function& func, llvm::Value& val) {
        return impl->NeedsDereference(func, val);
    }

    SpecLayoutOverride::Factory::Factory(
        anvill::Specification spec, TypeDecoder& type_decoder, bool stack_grows_down)
        : spec(spec)
        , type_decoder(type_decoder)
        , stack_grows_down(stack_grows_down) {}

    std::unique_ptr< FunctionLayoutOverride > SpecLayoutOverride::Factory::create(
        rellic::DecompilationContext& dec_ctx) {
        return std::make_unique< SpecLayoutOverride >(
            dec_ctx, spec, type_decoder, stack_grows_down);
    }
} // namespace irene3