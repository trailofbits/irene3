class ARMBackendObject: BackendObject {
    let namespace = "ARM";
}

class ARMMappingRecord
    < string from_name,
      string to_name,
      list<ValueType> apptypes,
      ValueType output_type >
    : MappingRecord<from_name, to_name, apptypes, output_type>
    , ARMBackendObject {}

class ARMPointerReg<string rname>: PointerReg<rname>, ARMBackendObject;

def : StackRegister<"SP">, ARMBackendObject {}

foreach Index = 0-12 in {
  def : ARMPointerReg<"R"#Index>;
  def : ARMMappingRecord<"R"#Index, "R"#Index, [i32,i16,i8], i32>;
}

def : ARMMappingRecord<"SP", "SP", [i32,i16,i8], i32>;
