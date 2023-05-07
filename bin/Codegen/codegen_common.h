//
// Created by Eric Kilmer on 3/10/23.
//

#ifndef IRENE3_CODEGEN_COMMON_H
#define IRENE3_CODEGEN_COMMON_H

#include <cstdint>
#include <llvm/Support/JSON.h>
#include <rellic/Result.h>
#include <string>
#include <unordered_set>

void SetVersion();

rellic::Result< llvm::json::Object, std::string > ProcessSpecification(
    const std::string& spec,
    std::unordered_set< uint64_t >& target_funcs,
    bool propagate_types,
    bool args_as_locals,
    bool unsafe_stack_locations,
    bool add_edges,
    bool is_vibes);
#endif // IRENE3_CODEGEN_COMMON_H
