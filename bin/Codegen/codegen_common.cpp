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

void GVarToSpec(
    const irene3::GlobalVarInfo &ginfo, llvm::json::Array &patch_vars, uint64_t address_size) {
    llvm::json::Array memory;
    memory.push_back("address");
    memory.push_back(to_hex(ginfo.address) + ":" + std::to_string(address_size));
    llvm::json::Object var;
    llvm::json::Array sclass;
    sclass.push_back("memory");
    sclass.push_back(std::move(memory));

    var["name"]          = ginfo.name;
    var["storage-class"] = std::move(sclass);
    patch_vars.push_back(std::move(var));
}

void FuncToSpec(
    const irene3::FunctionInfo finfo, llvm::json::Array &patch_vars, uint64_t addr_size) {
    llvm::json::Object var;
    var["name"] = finfo.name;
    llvm::json::Array arr;
    arr.push_back("constant");
    arr.push_back(to_hex(finfo.addr) + ":" + std::to_string(addr_size));

    var["storage-class"] = std::move(arr);
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
        for (const auto &c : bbcont.GetStackOffsetsAtEntry().affine_equalities) {
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
    const anvill::BasicBlockVariable &bb_param,
    const anvill::LowLoc &loc,
    const remill::Register *stack_pointer_reg,
    const StackOffsets &block_stack_disp,
    bool isVibes,
    bool unsafe,
    uint64_t address_size) {
    llvm::json::Array arr;
    if (loc.reg) {
        arr.push_back("register");

        std::stringstream ss;
        ss << loc.reg->name;
        if (loc.size) {
            ss << ":" << address_size;
        }
        if (!isVibes) {
            arr.push_back(ss.str());
        } else {
            llvm::json::Object reg;
            if (bb_param.live_at_entry) {
                reg["at-entry"] = ss.str();
            }

            if (bb_param.live_at_exit) {
                reg["at-exit"] = ss.str();
            }
            arr.push_back(std::move(reg));
        }
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
        memory.push_back(to_hex(offset) + ":" + std::to_string(address_size));
        arr.push_back(std::move(memory));
    } else {
        llvm::json::Array memory;
        memory.push_back("address");
        memory.push_back(to_hex(loc.mem_offset) + ":" + std::to_string(address_size));
        arr.push_back("memory");
        arr.push_back(std::move(memory));
    }

    return std::move(arr);
}

void ParamToSpecVibes(
    const anvill::BasicBlockVariable &bb_param,
    const remill::Register *stack_pointer_reg,
    const StackOffsets &block_stack_disp,
    llvm::json::Array &patch_vars,
    uint64_t address_size,
    bool unsafe = false) {
    auto var_spec = bb_param.param;
    llvm::json::Object var;
    var["name"] = bb_param.param.name;

    std::optional< llvm::json::Array > vstorage;
    if (bb_param.param.oredered_locs.size() == 1) {
        vstorage = LowLocToStorage(
            bb_param, bb_param.param.oredered_locs[0], stack_pointer_reg, block_stack_disp, true,
            unsafe, address_size);
    }

    if (!vstorage) {
        LOG(ERROR) << "Cannot generate patch def of composite inserting storage placeholder: "
                   << var_spec.name;

        var["storage-class"] = llvm::json::Array();
    } else {
        var["storage-class"] = std::move(*vstorage);
    }

    patch_vars.push_back(std::move(var));
}

void ParamToSpec(
    const anvill::BasicBlockVariable &bb_param,
    const remill::Register *stack_pointer_reg,
    const StackOffsets &block_stack_disp,
    llvm::json::Array &patch_vars,
    uint64_t address_size,
    bool unsafe = false) {
    auto var_spec = bb_param.param;
    llvm::json::Object var;
    var["name"] = var_spec.name;

    std::vector< llvm::json::Value > storage;

    for (const auto &loc : var_spec.oredered_locs) {
        auto comp = LowLocToStorage(
            bb_param, loc, stack_pointer_reg, block_stack_disp, false, address_size, unsafe);
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

static int64_t GetStackOffset(
    const remill::Arch &arch, const anvill::SpecStackOffsets &stack_offs) {
    auto sp_reg = arch.RegisterByName(arch.StackPointerRegisterName());
    for (auto &eq : stack_offs.affine_equalities) {
        if (eq.target_value.oredered_locs.size() != 1) {
            continue;
        }

        if (eq.target_value.oredered_locs[0].mem_reg) {
            continue;
        }

        if (eq.target_value.oredered_locs[0].reg == sp_reg) {
            return eq.stack_offset;
        }
    }
    LOG(ERROR) << "Couldn't find stack pointer";
    return 0;
}

rellic::Result< llvm::json::Object, std::string > ProcessSpecification(
    const std::string &spec_pb,
    std::unordered_set< uint64_t > &target_funcs,
    bool propagate_types,
    bool args_as_locals,
    bool unsafe_stack_locations,
    bool add_edges,
    bool is_vibes) {
    irene3::TypeDecoder type_decoder;
    auto maybe_spec = irene3::SpecDecompilationJobBuilder::CreateDefaultBuilder(
        spec_pb, propagate_types, args_as_locals, unsafe_stack_locations, type_decoder);
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
    uint64_t address_size  = spec.Arch()->address_size;
    for (auto &[addr, compound] : decomp_res.blocks) {
        const anvill::BasicBlockContext &block
            = block_contexts.GetBasicBlockContextForAddr(addr).value();

        llvm::json::Object patch;
        patch["patch-point"] = to_hex(addr) + ":" + std::to_string(address_size);

        auto func_decl      = spec.FunctionAt(block.GetParentFunctionAddress());
        auto cb             = func_decl->cfg.find(addr)->second;
        patch["patch-size"] = cb.size;

        patch["sp-align"] = GetStackOffset(*spec.Arch(), block.GetStackOffsetsAtExit())
                            - GetStackOffset(*spec.Arch(), block.GetStackOffsetsAtEntry());

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

        if (!unsafe_stack_locations) {
            patch_vars.push_back(llvm::json::Object{
                {  "name",                          "stack"     },
                {"memory",
                 llvm::json::Object{ { "frame-pointer", stack_pointer_reg->name },
                 { "offset", -stackoffs.stack_depth_at_entry } }}
            });
        }

        CHECK(fdecl);
        for (auto &bb_param : block.LiveParamsAtEntryAndExit()) {
            if (is_vibes) {
                ParamToSpecVibes(
                    bb_param, stack_pointer_reg, stackoffs, patch_vars, address_size,
                    unsafe_stack_locations);
            } else {
                ParamToSpec(
                    bb_param, stack_pointer_reg, stackoffs, patch_vars, address_size,
                    unsafe_stack_locations);
            }
        }

        for (const auto &gv : decomp_res.block_globals[addr]) {
            GVarToSpec(gv, patch_vars, address_size);
        }

        for (const auto &func : decomp_res.block_functions[addr]) {
            FuncToSpec(func, patch_vars, address_size);
        }

        patch["patch-vars"] = std::move(patch_vars);
        patches.push_back(std::move(patch));
    }

    llvm::json::Object result;
    result["patches"] = std::move(patches);
    return { result };
}
