// id really like to not use strings everywhere...

class PPCBackendObject: BackendObject {
    let namespace = "PPC";
}

class PPCMappingRecord
    < string from_name,
      string to_name,
      list<ValueType> apptypes,
      ValueType output_type >
    : MappingRecord<from_name, to_name, apptypes, output_type>
    , PPCBackendObject {}

class PPCPointerReg<string rname>: PointerReg<rname>, PPCBackendObject;

def : StackRegister<"R1">, PPCBackendObject {}

foreach Index = 0-31 in {
    def : PPCPointerReg<"R"#Index>;
}

// Just map GPRs for now as a test
foreach Index = 0-31 in {
  def : PPCMappingRecord<"R"#Index, "R"#Index, [i32,f32,i64,f64], i32>;

  def : PPCMappingRecord<"_R"#Index, "R"#Index, [i32,f32], i32>;
}

def : PPCMappingRecord<"BP", "BP", [i32,f32], i32>;
def : PPCMappingRecord<"FP", "FP", [i32,f32], i32>;