class NamedBackendObject<string ns> : BackendObject {
    let namespace = ns;
}

class X86PointerReg<string rname>: PointerReg<rname>, NamedBackendObject<"X86">;
class X86_64PointerReg<string rname>: PointerReg<rname>, NamedBackendObject<"X86_64">;

foreach RegName = ["A", "B", "C", "D"] in {
    def : X86_64PointerReg<"R"#RegName#"X">;
    def : X86PointerReg   <"E"#RegName#"X">;
}
def : X86_64PointerReg<"RSP">;
def : X86_64PointerReg<"RBP">;
def : X86_64PointerReg<"RSI">;
def : X86_64PointerReg<"RDI">;
def : StackRegister<"RSP">, NamedBackendObject<"X86_64"> {}

foreach Index = 8-15 in {
    def : X86_64PointerReg<"R"#Index>;
}

def : X86PointerReg<"ESP">;
def : X86PointerReg<"EBP">;
def : X86PointerReg<"ESI">;
def : X86PointerReg<"EDI">;
def : StackRegister<"ESP">, NamedBackendObject<"X86"> {}

multiclass IntelMappingRecords<string Backend> {
    foreach RegName = ["A", "B", "C", "D"] in {
        def : NamedBackendObject<Backend>, MappingRecord<"R"#RegName#"X", "R"#RegName#"X", [i64,i32,i16,i8], i64>;
        def : NamedBackendObject<Backend>, MappingRecord<"E"#RegName#"X", "E"#RegName#"X", [    i32,i16,i8], i32>;
        def : NamedBackendObject<Backend>, MappingRecord<RegName#"X"    , RegName#"X"    , [        i16,i8], i16>;
        def : NamedBackendObject<Backend>, MappingRecord<RegName#"L"    , RegName#"L"    , [            i8], i8>;
        def : NamedBackendObject<Backend>, MappingRecord<RegName#"H"    , RegName#"H"    , [            i8], i8>;
    }
    
    def : NamedBackendObject<Backend>, MappingRecord<"RSP", "RSP", [i64,i32,i16,i8], i64>;
    def : NamedBackendObject<Backend>, MappingRecord<"RBP", "RBP", [i64,i32,i16,i8], i64>;
    def : NamedBackendObject<Backend>, MappingRecord<"RSI", "RSI", [i64,i32,i16,i8], i64>;
    def : NamedBackendObject<Backend>, MappingRecord<"RDI", "RDI", [i64,i32,i16,i8], i64>;
    def : NamedBackendObject<Backend>, MappingRecord<"ESP", "ESP", [    i32,i16,i8], i32>;
    def : NamedBackendObject<Backend>, MappingRecord<"EBP", "EBP", [    i32,i16,i8], i32>;
    def : NamedBackendObject<Backend>, MappingRecord<"ESI", "ESI", [    i32,i16,i8], i32>;
    def : NamedBackendObject<Backend>, MappingRecord<"EDI", "EDI", [    i32,i16,i8], i32>;
    def : NamedBackendObject<Backend>, MappingRecord<"SP" , "SP" , [        i16,i8], i16>;
    def : NamedBackendObject<Backend>, MappingRecord<"BP" , "BP" , [        i16,i8], i16>;
    def : NamedBackendObject<Backend>, MappingRecord<"SI" , "SI" , [        i16,i8], i16>;
    def : NamedBackendObject<Backend>, MappingRecord<"DI" , "DI" , [        i16,i8], i16>;
    def : NamedBackendObject<Backend>, MappingRecord<"SPL", "SPL", [            i8], i8>;
    def : NamedBackendObject<Backend>, MappingRecord<"BPL", "BPL", [            i8], i8>;
    def : NamedBackendObject<Backend>, MappingRecord<"SIL", "SIL", [            i8], i8>;
    def : NamedBackendObject<Backend>, MappingRecord<"DIL", "DIL", [            i8], i8>;

    foreach Index = 8-15 in {
        def : NamedBackendObject<Backend>, MappingRecord<"R"#Index    , "R"#Index    , [i64,i32,i16,i8], i64>;
        def : NamedBackendObject<Backend>, MappingRecord<"R"#Index#"D", "R"#Index#"D", [    i32,i16,i8], i32>;
        def : NamedBackendObject<Backend>, MappingRecord<"R"#Index#"W", "R"#Index#"W", [        i16,i8], i16>;
        def : NamedBackendObject<Backend>, MappingRecord<"R"#Index#"B", "R"#Index#"B", [            i8], i8>;
    }

    foreach Index = 0-7 in {
        def : NamedBackendObject<Backend>, MappingRecord<"ST"#Index, "ST"#Index, [f80], f80>;
    }

    foreach Index = 0-31 in {
        def : NamedBackendObject<Backend>, MappingRecord<"ZMM"#Index, "ZMM"#Index, [v8f64,v16f32,v8i64,v16i32,v32i16]    , v8f64>;
        def : NamedBackendObject<Backend>, MappingRecord<"YMM"#Index, "YMM"#Index, [v4f64,v8f32 ,v4i64,v8i32 ,v16i16]    , v4f64>;
        def : NamedBackendObject<Backend>, MappingRecord<"XMM"#Index, "XMM"#Index, [v2f64,v4f32 ,v2i64,v4i32 ,v8i16,i128], v2f64>;
    }
}

defm : IntelMappingRecords<"X86">;
defm : IntelMappingRecords<"X86_64">;