/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

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
#include <remill/Arch/Arch.h>
#include <remill/BC/Error.h>
#include <remill/BC/Util.h>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>

DEFINE_string(spec, "", "input spec");
DEFINE_string(output, "", "output patch file");
DEFINE_string(lift_list, "", "list of entities to lift");
DEFINE_bool(add_edges, false, "add outgoing edges to blocks for cfg construction");
DEFINE_bool(type_propagation, false, "output patch file");
DEFINE_bool(unsafe_stack_locations, false, "create separate locals for each stack location");
DEFINE_bool(h, false, "help");

DECLARE_bool(version);
DECLARE_bool(help);

static void SetVersion(void) {
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
            if (c.target_value.mem_reg && c.target_value.mem_reg == stack_reg) {
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

void ParamToSpec(
    const anvill::BasicBlockVariable &bb_param,
    const remill::Register *stack_pointer_reg,
    const StackOffsets &block_stack_disp,
    llvm::json::Array &patch_vars,
    bool unsafe = false) {
    auto var_spec = bb_param.param;
    llvm::json::Object var;
    var["name"] = var_spec.name;
    if (var_spec.reg) {
        if (bb_param.live_at_entry) {
            var["at-entry"] = var_spec.reg->name;
        }

        if (bb_param.live_at_exit) {
            var["at-exit"] = var_spec.reg->name;
        }
    } else if (var_spec.mem_reg) {
        if (!unsafe && var_spec.mem_reg == stack_pointer_reg) {
            return;
        }

        // If this is a stack pointer variable then the "mem_offset is from the 0 of __anvill_rsp"
        // which is the pointer at the entrance of the function so we need displace this by the
        // stack depth

        auto offset = var_spec.mem_offset;
        if (var_spec.mem_reg == stack_pointer_reg) {
            // TODO(Ian): Do they support stack vars that live in different locations at entry and
            // exit??? we kinda need to for when the stack pointer shifts
            offset = var_spec.mem_offset - block_stack_disp.stack_depth_at_entry;
        }

        llvm::json::Object memory;
        memory["frame-pointer"] = var_spec.mem_reg->name;
        memory["offset"]
            = to_hex(offset) + ":" + std::to_string(var_spec.type->getScalarSizeInBits());
        var["memory"] = std::move(memory);
    } else {
        llvm::json::Object memory;
        memory["address"] = to_hex(var_spec.mem_offset) + ":"
                            + std::to_string(var_spec.type->getScalarSizeInBits());

        var["memory"] = std::move(memory);
    }
    patch_vars.push_back(std::move(var));
}

int main(int argc, char *argv[]) {
    SetVersion();
    google::SetUsageMessage("IRENE3 codegen");
    google::ParseCommandLineNonHelpFlags(&argc, &argv, false);
    google::InitGoogleLogging(argv[0]);

    if (argc <= 1 || FLAGS_help || FLAGS_h) {
        google::ShowUsageWithFlagsRestrict(argv[0], __FILE__);
        return EXIT_FAILURE;
    }

    google::HandleCommandLineHelpFlags();

    std::filesystem::path input_spec(FLAGS_spec);
    std::filesystem::path output_file(FLAGS_output);

    std::unordered_set< uint64_t > target_funcs;

    irene3::TypeDecoder type_decoder;
    auto maybe_spec = irene3::ProtobufPathToDecompilationBuilder(
        FLAGS_spec, FLAGS_type_propagation, /*args_as_locals=*/true, FLAGS_unsafe_stack_locations,
        type_decoder);
    if (!maybe_spec.Succeeded()) {
        std::cerr << maybe_spec.TakeError() << std::endl;
        return EXIT_FAILURE;
    }

    auto builder = maybe_spec.TakeValue();
    if (!FLAGS_lift_list.empty()) {
        std::stringstream ss(FLAGS_lift_list);

        for (uint64_t addr; ss >> std::hex >> addr;) {
            target_funcs.insert(addr);
            LOG(INFO) << "Added target " << std::hex << addr;
            if (ss.peek() == ',') {
                ss.ignore();
            }
        }

        builder.target_funcs = target_funcs;
    }

    irene3::SpecDecompilationJob job(std::move(builder));
    auto maybe_decomp_res = job.DecompileBlocks();
    if (!maybe_decomp_res.Succeeded()) {
        std::cerr << maybe_decomp_res.TakeError() << std::endl;
        return EXIT_FAILURE;
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

        if (FLAGS_add_edges) {
            llvm::json::Array edges;

            auto func_decl = spec.FunctionAt(block.GetParentFunctionAddress());
            auto cb        = func_decl->cfg.find(addr)->second;
            for (auto e : cb.outgoing_edges) {
                edges.push_back(to_hex(e));
            }

            patch["edges"] = std::move(edges);
        }

        patch["patch-code"] = PrintBodyToString(compound);

        llvm::json::Array patch_vars;
        patch_vars.push_back(llvm::json::Object{
            {  "name",                                                      "stack"},
            {"memory", llvm::json::Object{ { "frame-pointer", stack_pointer_reg->name },
 { "offset", 0 } }                                           }
        });

        auto fdecl = spec.FunctionAt(block.GetParentFunctionAddress());
        CHECK(fdecl);
        auto stackoffs = ComputeStackOffsets(stack_pointer_reg, *fdecl, addr);
        for (auto &bb_param : block.LiveParamsAtEntryAndExit()) {
            ParamToSpec(
                bb_param, stack_pointer_reg, stackoffs, patch_vars, FLAGS_unsafe_stack_locations);
        }

        for (const auto &gv : decomp_res.block_globals[addr]) {
            GVarToSpec(gv, patch_vars);
        }

        patch["patch-vars"] = std::move(patch_vars);
        patches.push_back(std::move(patch));
    }

    llvm::json::Object result;
    result["patches"] = std::move(patches);

    if (!FLAGS_output.empty()) {
        std::error_code ec;
        llvm::raw_fd_ostream output(FLAGS_output, ec);
        if (ec) {
            std::cerr << "Could not open output file " << FLAGS_output << std::endl;
            return EXIT_FAILURE;
        }

        output << llvm::json::Value(std::move(result));
    }

    return EXIT_SUCCESS;
}
