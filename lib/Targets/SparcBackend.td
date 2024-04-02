class SPARCBackendObject: BackendObject {
    let namespace = "SPARC";
}

class SPARCMappingRecord
    < string from_name,
      string to_name,
      list<ValueType> apptypes,
      ValueType output_type >
    : MappingRecord<from_name, to_name, apptypes, output_type>
    , SPARCBackendObject {}

class SPARCPointerReg<string rname>: PointerReg<rname>, SPARCBackendObject;

def : StackRegister<"SP">, SPARCBackendObject {}


foreach Index = 0-31 in {
    def : SPARCMappingRecord<"FS"#Index, "F"#Index, [i32, f32], f32>;
}

foreach Index = 0-7 in {
    foreach Rtype = ["G", "I", "O", "L"] in { 
        def : SPARCPointerReg<Rtype # Index>;
        def : SPARCMappingRecord<Rtype # Index, Rtype # Index, [i32, i16, i8], i32>;
    }
}

/* dont support pairs directly for now, instead we split them in ghidra
foreach Index = [0, 2, 4, 6] in  {
    defvar Succ = !add(Index, 1);
    foreach Rtype = ["G", "I", "O", "L"] in { 
        def : SPARCMappingRecord<Rtype # Index # "_" # Succ, Rtype # Index # "_" # Rtype # Succ, [i64, i32], v2i32>; 
    }
}*/