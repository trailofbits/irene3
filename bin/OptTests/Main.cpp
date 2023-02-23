#include <iostream>
#include <llvm/ADT/APInt.h>
#include <llvm/IR/Constant.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

int main(int argc, char* argv[]) {
    llvm::LLVMContext context;
    llvm::Module mod("", context);
    mod.setDataLayout("e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128");
    auto dl        = mod.getDataLayout();
    llvm::Type* ty = llvm::IntegerType::getInt64Ty(context);

    llvm::Type* sty = llvm::StructType::create(context, { ty, ty });
    auto off        = llvm::APInt(64, 8);
    auto inds       = dl.getGEPIndexForOffset(sty, off);
    if (inds) {
        std::cout << mod.getDataLayoutStr() << std::endl;
        std::cout << (*inds).getLimitedValue() << std::endl;
    }
}