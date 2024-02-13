#include <irene3/PhysicalLocationDecoder.h>
#include <llvm/CodeGen/MachineValueType.h>
#include <llvm/CodeGen/TargetRegisterInfo.h>
#include <optional>
#include <variant>
#include <vector>
namespace irene3
{
    PhysTypeTranslator::PhysTypeTranslator(const llvm::TargetRegisterInfo *r)
        : reg_info(r) {
        this->reg_table.Populate(r);
    }

} // namespace irene3