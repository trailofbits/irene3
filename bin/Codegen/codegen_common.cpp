/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "codegen_common.h"

#include <anvill/ABI.h>
#include <anvill/Declarations.h>
#include <anvill/Lifters.h>
#include <anvill/Optimize.h>
#include <anvill/Providers.h>
#include <anvill/Specification.h>
#include <clang/AST/Expr.h>
#include <clang/AST/GlobalDecl.h>
#include <clang/AST/Stmt.h>
#include <clang/Basic/LLVM.h>
#include <clang/Tooling/Tooling.h>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <iostream>
#include <irene3/DecompileSpec.h>
#include <irene3/TypeDecoder.h>
#include <irene3/Util.h>
#include <irene3/Version.h>
#include <llvm/ADT/Triple.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/raw_ostream.h>
#include <optional>
#include <rellic/Decompiler.h>
#include <rellic/Result.h>
#include <remill/Arch/Arch.h>
#include <remill/BC/Error.h>
#include <remill/BC/Util.h>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

void SetVersion(void) {
    std::stringstream version;

    auto vs = irene3::Version::GetVersionString();
    if (0 == vs.size()) {
        vs = "unknown";
    }
    version << vs << "\n";
    if (!irene3::Version::HasVersionData()) {
        version << "No extended version information found!\n";
    } else {
        version << "Commit Hash: " << irene3::Version::GetCommitHash() << "\n";
        version << "Commit Date: " << irene3::Version::GetCommitDate() << "\n";
        version << "Last commit by: " << irene3::Version::GetAuthorName() << " ["
                << irene3::Version::GetAuthorEmail() << "]\n";
        version << "Commit Subject: [" << irene3::Version::GetCommitSubject() << "]\n";
        version << "\n";
        if (irene3::Version::HasUncommittedChanges()) {
            version << "Uncommitted changes were present during build.\n";
        } else {
            version << "All changes were committed prior to building.\n";
        }
    }
    version << "Using LLVM " << LLVM_VERSION_STRING << std::endl;

    google::SetVersionString(version.str());
}

template< typename T >
std::string to_hex(T &&value) {
    std::stringstream ss;
    ss << "0x" << std::hex << std::forward< T >(value);
    return ss.str();
}

std::string PrintBodyToString(clang::CompoundStmt *compound);
std::string PrintStmtToString(clang::Stmt *st) {
    if (clang::isa< clang::ReturnStmt >(st)) {
        return "";
    }

    if (auto comp = clang::dyn_cast< clang::CompoundStmt >(st)) {
        return PrintBodyToString(comp);
    }

    std::string code;
    llvm::raw_string_ostream os(code);

    if (auto call = clang::dyn_cast< clang::CallExpr >(st)) {
        auto callee    = call->getCallee();
        auto maybe_ref = callee->IgnoreCasts();
        if (auto ref = clang::dyn_cast< clang::DeclRefExpr >(maybe_ref)) {
            if (ref->getDecl()->getDeclName().getAsString() == anvill::kAnvillGoto) {
                auto target_addr = clang::cast< clang::IntegerLiteral >(call->getArg(0));
                // TODO(Ian): 64 bit is fine for now...
                os << "goto L_" << to_hex(target_addr->getValue().getLimitedValue());
                os << ";\n";
                return code;
            }

            if (ref->getDecl()->getDeclName().getAsString() == anvill::kAnvillBasicBlockReturn
                && call->getNumArgs() <= 1) {
                os << "return ";
                if (call->getNumArgs() == 1) {
                    os << PrintStmtToString(call->getArg(0));
                }

                return code;
            }
        }
    }

    if (auto ifst = clang::dyn_cast< clang::IfStmt >(st)) {
        os << "if (";
        ifst->getCond()->printPretty(os, nullptr, { {} });
        os << ") { \n";
        os << PrintStmtToString(ifst->getThen());
        os << "}";

        if (ifst->getElse()) {
            os << " else { \n";
            os << PrintStmtToString(ifst->getElse());
            os << "}";
        }
        os << "\n";
        return code;
    }

    st->printPretty(os, nullptr, { {} });
    if (clang::isa< clang::Expr >(st)) {
        os << ";\n";
    }

    return code;
}

std::string PrintBodyToString(clang::CompoundStmt *compound) {
    std::string code;
    llvm::raw_string_ostream os(code);
    for (auto &stmt : compound->body()) {
        os << PrintStmtToString(stmt);
    }
    return code;
}

void GVarToSpec(const irene3::GlobalVarInfo &ginfo, llvm::json::Array &patch_vars) {
    llvm::json::Object memory;
    memory["address"] = to_hex(ginfo.address) + ":" + std::to_string(ginfo.size);
    llvm::json::Object var;
    var["name"]   = ginfo.name;
    var["memory"] = std::move(memory);
    patch_vars.push_back(std::move(var));
}

namespace
{
    struct StackOffsets {
        std::int64_t stack_depth_at_entry;
        std::int64_t stack_depth_at_exit;
    };

    std::optional< std::int64_t > GetDepthForBlockEntry(
        const remill::Register *stack_reg, const anvill::BasicBlockContext &bbcont) {
        for (const auto &c : bbcont.GetStackOffsets().affine_equalities) {
            if (c.target_value.oredered_locs.size() == 1 && c.target_value.oredered_locs[0].reg
                && c.target_value.oredered_locs[0].reg == stack_reg) {
                return c.stack_offset;
            }
        }
        return std::nullopt;
    }

    std::optional< std::int64_t > GetDepthForBlockExit(
        const remill::Register *stack_reg, const anvill::FunctionDecl &decl, uint64_t bbaddr) {
        auto nd = decl.cfg.at(bbaddr);

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
        const remill::Register *stack_reg, const anvill::FunctionDecl &decl, uint64_t bbaddr) {
        auto cont       = decl.GetBlockContext(bbaddr);
        auto ent_depth  = GetDepthForBlockEntry(stack_reg, cont);
        auto exit_depth = GetDepthForBlockExit(stack_reg, decl, bbaddr);

        if (!ent_depth) {
            LOG(ERROR) << "Overriding entry depth with 0";
        }

        if (!exit_depth) {
            LOG(ERROR) << "Overriding exit depth with 0";
        }

        return { ent_depth.value_or(0), exit_depth.value_or(0) };
    }

} // namespace
std::optional< llvm::json::Array > LowLocToStorage(
    const anvill::LowLoc &loc,
    const remill::Register *stack_pointer_reg,
    const StackOffsets &block_stack_disp,
    bool unsafe) {
    llvm::json::Array arr;
    if (loc.reg) {
        arr.push_back("register");

        std::stringstream ss;
        ss << loc.reg->name;
        if (loc.size) {
            ss << ":" << *loc.size;
        }
        arr.push_back(ss.str());
    } else if (loc.mem_reg) {
        if (!unsafe && loc.mem_reg == stack_pointer_reg) {
            return std::nullopt;
        }
        arr.push_back("memory");
        llvm::json::Array memory;

        // If this is a stack pointer variable then the "mem_offset is from the 0 of __anvill_rsp"
        // which is the pointer at the entrance of the function so we need displace this by the
        // stack depth

        auto offset = loc.mem_offset;
        if (loc.mem_reg == stack_pointer_reg) {
            // TODO(Ian): Do they support stack vars that live in different locations at entry and
            // exit??? we kinda need to for when the stack pointer shifts
            offset = loc.mem_offset - block_stack_disp.stack_depth_at_entry;
        }
        memory.push_back("frame");
        memory.push_back(loc.mem_reg->name);
        memory.push_back(to_hex(offset) + ":" + std::to_string(loc.Size()));
        arr.push_back(std::move(memory));
    } else {
        llvm::json::Array memory;
        memory.push_back("address");
        memory.push_back(to_hex(loc.mem_offset) + ":" + std::to_string(loc.Size()));
        arr.push_back("memory");
        arr.push_back(std::move(memory));
    }

    return std::move(arr);
}

void ParamToSpec(
    const anvill::BasicBlockVariable &bb_param,
    const remill::Register *stack_pointer_reg,
    const StackOffsets &block_stack_disp,
    llvm::json::Array &patch_vars,
    bool unsafe = false) {
    auto var_spec = bb_param.param;
    llvm::json::Object var;
    var["name"] = var_spec.name;

    std::vector< llvm::json::Value > storage;

    for (const auto &loc : var_spec.oredered_locs) {
        auto comp = LowLocToStorage(loc, stack_pointer_reg, block_stack_disp, unsafe);
        if (comp) {
            storage.push_back(std::move(*comp));
        } else {
            return;
        }
    }

    if (bb_param.live_at_entry) {
        var["at-entry"] = storage;
    }

    if (bb_param.live_at_exit) {
        var["at-exit"] = storage;
    }

    patch_vars.push_back(std::move(var));
}

rellic::Result< llvm::json::Object, std::string > ProcessSpecification(
    std::filesystem::path &in_spec,
    std::unordered_set< uint64_t > &target_funcs,
    bool propagate_types,
    bool args_as_locals,
    bool unsafe_stack_locations,
    bool add_edges) {
    irene3::TypeDecoder type_decoder;
    auto maybe_spec = irene3::ProtobufPathToDecompilationBuilder(
        in_spec, propagate_types, args_as_locals, unsafe_stack_locations, type_decoder);
    if (!maybe_spec.Succeeded()) {
        return { std::string(maybe_spec.TakeError()) };
    }

    auto builder = maybe_spec.TakeValue();
    if (!target_funcs.empty()) {
        builder.target_funcs = target_funcs;
    }

    irene3::SpecDecompilationJob job(std::move(builder));
    auto maybe_decomp_res = job.DecompileBlocks();
    if (!maybe_decomp_res.Succeeded()) {
        return { std::string(maybe_decomp_res.TakeError()) };
    }
    auto decomp_res = maybe_decomp_res.TakeValue();

    auto &spec          = builder.GetSpec();
    auto block_contexts = spec.GetBlockContexts();
    llvm::json::Array patches;

    auto stack_pointer_reg = spec.Arch()->RegisterByName(spec.Arch()->StackPointerRegisterName());

    for (auto &[addr, compound] : decomp_res.blocks) {
        const anvill::BasicBlockContext &block
            = block_contexts.GetBasicBlockContextForAddr(addr).value();

        llvm::json::Object patch;
        patch["patch-name"] = "block_" + std::to_string(addr);
        patch["patch-addr"] = to_hex(addr);

        auto func_decl      = spec.FunctionAt(block.GetParentFunctionAddress());
        auto cb             = func_decl->cfg.find(addr)->second;
        patch["patch-size"] = to_hex(cb.size);

        if (add_edges) {
            llvm::json::Array edges;

            for (auto e : cb.outgoing_edges) {
                edges.push_back(to_hex(e));
            }

            patch["edges"] = std::move(edges);
        }

        patch["patch-code"] = PrintBodyToString(compound);

        llvm::json::Array patch_vars;

        auto fdecl     = spec.FunctionAt(block.GetParentFunctionAddress());
        auto stackoffs = ComputeStackOffsets(stack_pointer_reg, *fdecl, addr);

        patch_vars.push_back(llvm::json::Object{
            {  "name",                                                                                    "stack"},
            {"memory", llvm::json::Object{ { "frame-pointer", stack_pointer_reg->name },
 { "offset", -stackoffs.stack_depth_at_entry } }                                           }
        });

        CHECK(fdecl);
        for (auto &bb_param : block.LiveParamsAtEntryAndExit()) {
            ParamToSpec(bb_param, stack_pointer_reg, stackoffs, patch_vars, unsafe_stack_locations);
        }

        for (const auto &gv : decomp_res.block_globals[addr]) {
            GVarToSpec(gv, patch_vars);
        }

        patch["patch-vars"] = std::move(patch_vars);
        patches.push_back(std::move(patch));
    }

    llvm::json::Object result;
    result["patches"] = std::move(patches);
    return { result };
}
