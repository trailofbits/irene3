include "llvm/CodeGen/ValueTypes.td"

// id really like to not use strings everywhere...


class BackendObject {
    string namespace = "";
}

class StackRegister<string rname> {
    string reg_name = rname;
}


class PPCBackendObject: BackendObject {
    let namespace = "PPC";
}

def PPCStackReg: StackRegister<"R1">, PPCBackendObject {}



// Mapping Records are the list of types that produce a mapping record
class MappingRecord<string from_name, string to_name, list<ValueType> apptypes, ValueType output_type>: PPCBackendObject {
    string from = from_name;
    string to = to_name;
    list<ValueType> applicable_types = apptypes;
    ValueType output = output_type;
}


class PPCMappingRecord<string from_name, string to_name, list<ValueType> apptypes, ValueType output_type> : MappingRecord<from_name, to_name, apptypes, output_type> {

}



class PointerReg<string rname> {
    string reg_name = rname;
}

class PPCPointerReg<string rname>: PointerReg<rname>, PPCBackendObject;

foreach Index = 0-31 in {
    def PointerReg_R#Index: PPCPointerReg<"R"#Index>;
}

// Just map GPRs for now as a test
foreach Index = 0-31 in {
  def R#Index : PPCMappingRecord<"R"#Index, "R"#Index, [i32,f32,i64,f64], i32>;

  def _R#Index : PPCMappingRecord<"_R"#Index, "R"#Index, [i32,f32], i32>;
}

def BP : PPCMappingRecord<"BP", "BP", [i32,f32], i32>;
def FP : PPCMappingRecord<"FP", "FP", [i32,f32], i32>;