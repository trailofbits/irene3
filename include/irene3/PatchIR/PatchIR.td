#ifndef PATCHIR_DIALECT
#define PATCHIR_DIALECT

include "mlir/IR/OpBase.td"
include "mlir/IR/AttrTypeBase.td"
include "mlir/IR/BuiltinAttributes.td"

def PatchIR_Dialect : Dialect {
    let name = "patchir";
    let summary = "IRENE3 PatchIR dialect.";
    let description = [{
        IRENE3 PatchIR dialect.
    }];
    let cppNamespace = "::irene3::patchir";

    let extraClassDeclaration = [{
        void registerTypes();
        void registerAttrs();

        static llvm::StringRef getImageBaseAttrName() { return "patchir.image_base"; }
    }];

    // Uncomment if adding custom types
    let useDefaultTypePrinterParser = 1;
    let useDefaultAttributePrinterParser = 1;
}

class PatchIR_Op<string mnemonic, list<Trait> traits = []> :
        Op<PatchIR_Dialect, !strconcat("irene.", mnemonic), traits>;

class PatchIR_Type<string name, string typeMnemonic, list<Trait> traits = []> :
        TypeDef<PatchIR_Dialect, name, traits> {
    let mnemonic = typeMnemonic;
}

class PatchIR_Attr<string name, string attrMnemonic, list<Trait> traits = []>
    : AttrDef<PatchIR_Dialect, name, traits> {
  let mnemonic = attrMnemonic;
}

include "PatchIRTypes.td"
include "PatchIRAttrs.td"
include "PatchIROps.td"

#endif // PATCHIR_DIALECT