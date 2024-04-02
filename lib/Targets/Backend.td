include "llvm/CodeGen/ValueTypes.td"

// Mapping Records are the list of types that produce a mapping record
class MappingRecord<string from_name, string to_name, list<ValueType> apptypes, ValueType output_type> {
    string from = from_name;
    string to = to_name;
    list<ValueType> applicable_types = apptypes;
    ValueType output = output_type;
}

class PointerReg<string rname> {
    string reg_name = rname;
}

class StackRegister<string rname> {
    string reg_name = rname;
}

class BackendObject {
    string namespace = "";
}

include "PPCBackend.td"
include "X86Backend.td"
include "ARMBackend.td"
include "SparcBackend.td"