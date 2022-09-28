#include <JsonDecompBuilder.h>
#include <irene3/Util.h>
#include <llvm/Support/raw_ostream.h>

// TODO(Ian): we need to collect all top level decls that arent functions and print them somewhere

namespace
{
    pasta::PrintedTokenRange GetTokenRange(clang::FunctionDecl *clang_func) {
        clang::PrintingPolicy pp(clang_func->getASTContext().getPrintingPolicy());
        return pasta::PrintedTokenRange::Create(clang_func->getASTContext(), pp, clang_func);
    }
    void AddWhitespaceAttributes(llvm::json::OStream &os, const pasta::PrintedToken &tok) {
        os.attribute("leading_new_lines", llvm::json::Value(tok.NumLeadingNewLines()));
        os.attribute("leading_spaces", llvm::json::Value(tok.NumleadingSpaces()));
    }

    llvm::json::Value LLVMValueToJson(const llvm::Value *val) {
        std::string output;
        llvm::raw_string_ostream ss(output);
        val->print(ss);
        return llvm::json::Value(output);
    }
} // namespace

void JsonDecompBuilder::WriteToStream(llvm::json::OStream &os, const irene3::FunctionDecomp &func) {
    auto tok_range = GetTokenRange(func.clang_func);

    for (auto tok : tok_range) {
        AvailableTokenProvenanceInfo prov = this->GetTokenProvenance(tok, func);

        os.object([&] {
            os.attribute("data", llvm::json::Value(tok.Data()));
            // TODO(ian): should we use the closest value here regardless of where
            // pc came from?
            if (prov.pc_value.has_value()) {
                os.attribute("bitcode", LLVMValueToJson(*prov.pc_value));
            } else if (prov.value.has_value()) {
                os.attribute("bitcode", LLVMValueToJson(*prov.value));
            }
            if (prov.pc.has_value()) {
                os.attribute("pc", llvm::json::Value(*prov.pc));
            }

            AddWhitespaceAttributes(os, tok);
        });
    }
}
JsonDecompBuilder::JsonDecompBuilder(const irene3::DecompilationResult &result_)
    : result(result_) {}

void JsonDecompBuilder::WriteOut(llvm::raw_ostream &os) {
    llvm::json::OStream js(os);

    js.object([&] {
        js.attributeArray("functions", [&] {
            for (const auto &func : this->result.function_results) {
                js.object([&] {
                    js.attribute("address", llvm::json::Value(func.first));

                    if (func.second.Succeeded()) {
                        js.attribute(
                            "symbol", llvm::json::Value(func.second->llmv_func->getName()));
                        js.attribute(
                            "return_type",
                            llvm::json::Value(
                                func.second->clang_func->getReturnType().getAsString()));
                        js.attributeArray("parameters", [&] {
                            for (auto param : func.second->clang_func->parameters()) {
                                js.object([&] {
                                    js.attribute("name", param->getName());
                                    js.attribute("type", param->getType().getAsString());
                                });
                            }
                        });
                        js.attributeArray(
                            "tokens", [&] { WriteToStream(js, func.second.Value()); });

                    } else {
                        js.attribute("decomp_error", func.second.Error());
                    }
                });
            }
        });
    });
}

AvailableTokenProvenanceInfo JsonDecompBuilder::GetTokenProvenance(
    const pasta::PrintedToken &tok, const irene3::FunctionDecomp &func) {
    AvailableTokenProvenanceInfo res;

    // Drill down through the token context and identify the closest value
    // associated with a program counter.

    if (auto maybe_context = tok.Context()) {
        pasta::TokenContext context = std::move(*maybe_context);
        do {
            context.TryUpdateToAliasee();
            if (context.Kind() == pasta::TokenContextKind::kStmt) {
                // TODO(Ian): this is what old IRENE did but we shouldnt do this...
                auto stmt = reinterpret_cast< clang::Stmt * >(const_cast< void * >(context.Data()));
                if (auto val_it = this->result.prov_info.ValueAssociatedWithStatement(stmt)) {
                    if (!res.value.has_value()) {
                        res.value = *val_it;
                    }

                    res.pc = irene3::GetPCMetadata(*val_it);

                    if (res.pc.has_value()) {
                        res.pc_value = val_it;
                        break;
                    }
                }
            }
        } while (context.TryUpdateToParent());
    }

    return res;
}
