#pragma once

#include <irene3/DecompileSpec.h>
#include <llvm/Support/raw_ostream.h>
#include <pasta/AST/Printer.h>
#include <pasta/AST/Token.h>
#include <stdint.h>

struct AvailableTokenProvenanceInfo {
    std::optional< uint64_t > pc;
    // closest value
    std::optional< const llvm::Value * > value;
    // closest value with pc metadata
    std::optional< const llvm::Value * > pc_value;
};

class JsonDecompBuilder {
  private:
    const irene3::DecompilationResult &result;

    AvailableTokenProvenanceInfo GetTokenProvenance(
        const pasta::PrintedToken &tok, const irene3::FunctionDecomp &func);
    void WriteToStream(llvm::json::OStream &os, const irene3::FunctionDecomp &func);

  public:
    JsonDecompBuilder(const irene3::DecompilationResult &result);
    void WriteOut(llvm::raw_ostream &);
};