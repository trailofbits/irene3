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
    std::optional< std::vector< llvm::MVT > > PhysTypeTranslator::ComputeComponentAssignments(
        llvm::Type *target_type, LowLoc lowloc) {
        return std::visit(
            overload{ [target_type](
                          const std::monostate &mon) -> std::optional< std::vector< llvm::MVT > > {
                         return { { llvm::MVT::getIntegerVT(
                             target_type->getPrimitiveSizeInBits().getFixedValue()) } };
                     },
                      [](const irene3::patchir::MemoryIndirectAttr &indirect)
                          -> std::optional< std::vector< llvm::MVT > > {
                          // need to actually break this up into fields do abi things...
                          return { { llvm::MVT::getIntegerVT(indirect.getSizeBits()) } };
                      },
                      [this](const irene3::patchir::RegisterAttr &indirect)
                          -> std::optional< std::vector< llvm::MVT > > {
                          auto maybe_reg = this->reg_table.lookup(indirect.getReg().str());

                          for (auto r : this->reg_info->regclasses()) {
                              if (r->contains(*maybe_reg)) {
                                  LOG(ERROR)
                                      << "Looking in class " << this->reg_info->getRegClassName(r)
                                      << " " << r->MC->getSizeInBits()
                                      << " target size: " << indirect.getSizeBits()
                                      << " is subclass " << r->isASubClass();
                                  if (r->MC->getSizeInBits() == indirect.getSizeBits()) {
                                      LOG(ERROR)
                                          << "Found in " << this->reg_info->getRegClassName(r);
                                      for (llvm::TargetRegisterInfo::vt_iterator st
                                           = this->reg_info->legalclasstypes_begin(*r),
                                           end = this->reg_info->legalclasstypes_end(*r);
                                           st != end; st++) {
                                          return { { *st } };
                                      }
                                  }
                              }
                          }
                          return std::nullopt;
                      },
                      [](const irene3::patchir::MemoryAttr &indirect)
                          -> std::optional< std::vector< llvm::MVT > > {
                          return { { llvm::MVT::getIntegerVT(indirect.getSizeBits()) } };
                      } },
            lowloc);
    }
} // namespace irene3