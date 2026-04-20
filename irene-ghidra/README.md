# Irene Ghidra Plugin

This plugin adds two ghidra exporters that export the anvill specification in JSON and protobuf formats.

## iOS / macOS Mach-O support

Phase 0–6 of the per-phase plan adds Apple-platform spec extraction.
Mach-O binaries now emit ObjC and Swift metadata through the
`Specification.symbols` channel using well-known sentinel name
prefixes (see `anvill.macho.ArcRuntime`).

### Support matrix

| Binary flavour          | OS tag  | Arch tag      | Call conv           | ObjC         | Swift        | ARC          | Notes                                         |
|-------------------------|---------|---------------|---------------------|--------------|--------------|--------------|-----------------------------------------------|
| x86_64 Mach-O           | MACOS   | AMD64         | existing x86 table  | n/a          | n/a          | n/a          | Pre-Phase-0 baseline; zero regressions.       |
| arm64 macOS             | MACOS   | AARCH64       | AARCH64_DARWIN[†]   | full         | full         | full         |                                               |
| arm64 iOS               | IOS[†]  | AARCH64       | AARCH64_DARWIN[†]   | full         | full         | full         | Platform via `LC_BUILD_VERSION` / `LC_VERSION_MIN_IPHONEOS`. |
| arm64 tvOS / watchOS    | TVOS[†] / WATCHOS[†] | AARCH64 | AARCH64_DARWIN[†] | full         | full         | full         | Tag via `LC_BUILD_VERSION.platform`.          |
| arm64e (PAC)            | MACOS / IOS | AARCH64E[†] | AARCH64_DARWIN[†] | full         | full         | full         | Detection only. remill does not yet lift PAC instructions — lifted IR treats PAC as strip. See plan §9. |
| FairPlay-encrypted iOS  | fail-fast | n/a         | n/a                 | n/a          | n/a          | n/a          | `MachoEncryptedException(cryptid)` raised before any spec output. |
| dyld-shared-cache dylibs | n/a    | n/a           | n/a                 | n/a          | n/a          | n/a          | Out of scope — extract individual dylibs first. |

[†] Currently emitted through `EnumShim` reflection: if the
vendored `vendor/anvill/data_specifications/specification.proto` has
the new enum values, the real value is used. Otherwise the shim falls
back (`OS_IOS → OS_MACOS`, `ARCH_AARCH64E → ARCH_AARCH64`,
`AARCH64_DARWIN → CDECL`, `SWIFTCALL → CDECL`, …) with a one-shot
console warning. The proto PR lives on the `vendor/anvill-ios-macho-enums`
branch of the submodule and on the `vendor/anvill-ios-macho-enums`
branch of the parent repo (submodule pointer bump). Once merged
upstream the shim collapses to a direct identity mapping.

### Sentinel channel

Every ObjC / Swift fact is emitted as a `Specification.symbols`
entry with a well-known name prefix. The downstream lifter can
filter by `symbol.name.startsWith(prefix)`:

| Prefix                                   | Meaning                                                |
|------------------------------------------|--------------------------------------------------------|
| `__irene_objc_class_<Name>`              | ObjC class (address = `_OBJC_CLASS_$_<Name>` label)    |
| `__irene_objc_method_<hex>_<±>[Class sel]` | ObjC method, address = entry point                   |
| `__irene_objc_protocol_<Name>`           | ObjC protocol (address = `_OBJC_PROTOCOL_$_<Name>`)    |
| `__irene_objc_category_<hex>_<±>[Class(Cat) sel]` | ObjC category method (class + category + selector) |
| `__irene_objc_selref_<hex>`              | `__objc_selrefs` slot                                  |
| `__irene_objc_msgsend_<variant>_<hex>`   | `objc_msgSend` family call site                        |
| `__irene_arc_<kind>_<hex>`               | ObjC or Swift ARC runtime call site                    |
| `__irene_arc_pair_<ret>_<mark>_<arc>`    | retain-autoreleased-return marker-nop triple           |
| `__irene_swift_func_<hex>_<mangled>`     | Swift function identity                                |
| `__irene_swift_demangled_<hex>_<name>`   | Swift demangled display name (mangled fallback on Ghidra < 11) |
| `__irene_swift_async_<hex>`              | Swift async (YaF / YaK) variant                        |
| `__irene_swift_pin_{self,error,async}_<hex>` | swiftself (x20) / swifterror (x21) / swiftasync (x22) register pin |
| `__irene_swift5_<section>_<hex>`         | `__swift5_*` metadata section start                    |

### Test binaries

Committed micro-fixtures under
`src/test/resources/binaries/` (see `SOURCES.md` alongside them for
reproduction recipes):

| Fixture                          | Purpose                                |
|----------------------------------|----------------------------------------|
| `arm64-macos-collatz`            | Plain C, arm64 Mach-O                  |
| `arm64-macos-objc-hello.dylib`   | ObjC with Foundation, `-fobjc-arc`     |
| `arm64-macos-objc-categories.dylib` | ObjC with a protocol + category     |
| `arm64-macos-swift-hello`        | Swift executable                       |
| `arm64e-macos-sample`            | arm64e (CPU_SUBTYPE_ARM64E)            |
| `arm64-ios-encrypted-stub`       | iOS Mach-O with cryptid patched to 1   |

### Integration harness

`tests/integration/macho/run.sh` drives every fixture through Ghidra
headless + `anvillHeadlessExportScript.java` and diffs the output
against the committed `.phase6.spec.pb` goldens.

```
GHIDRA_INSTALL_DIR=/path/to/amp-ghidra \
JAVA_HOME=/opt/homebrew/opt/openjdk@17 \
tests/integration/macho/run.sh
```

### Companion scripts

- `scripts/slice_fat_macho.py` — split a FAT_MAGIC / FAT_MAGIC_64
  binary into per-arch Mach-O slices (stdlib-only, no `lipo` needed).
  Used for workflows that don't go through Ghidra's loader.
- `scripts/extract_from_dyld_cache.py` — front-end over `ipsw` /
  Apple's `dsc_extractor` for pulling individual dylibs out of an
  iOS shared cache. Run `… check` to see which backends are on PATH
  and their install hints.

### Real-world smoke

A local-only smoke harness (`FreeOtpSmokeTest`, not committed) runs
the Apple extractors against the FreeOTP iOS app binary. Typical
output on a 541 KB arm64 iOS binary: 28 ObjC classes, 216 methods,
1542 msgSend call sites, 320 Swift functions, 4365 ARC call sites,
10 `__swift5_*` sections — extracted in < 40 s.

### Known gaps

- **arm64e PAC lifting**. remill does not yet implement
  `pacia` / `autia` / `braa` / `retab` semantics. Spec metadata is
  ready; lift fidelity on arm64e binaries is gated on upstream.
- **Swift demangling**. Requires Ghidra 11+ for a built-in
  demangler; on older Ghidra the `__irene_swift_demangled_*` sentinel
  carries the raw mangled name and a one-shot warning is logged.
  Downstream consumers can pipe through `xcrun swift-demangle`.
- **Full pipeline on large binaries**. The existing
  `anvill.MappingDomain.join` type-constraint solver scales
  super-linearly with function count and times out on mid-sized iOS
  apps (~4.5k functions). The Apple extractors themselves finish in
  tens of seconds — unrelated to Mach-O work.
- **dyld shared-cache extraction**. Out of scope; supply individual
  dylibs extracted via an external tool.
