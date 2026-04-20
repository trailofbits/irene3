# iOS / Mach-O support — progress report

Summary of the Phase 0–6 work adding iOS Mach-O spec extraction to
`irene-ghidra`. Scope is limited to the Ghidra-side extractor; the
C++ lifter pipeline (`bin/Decompile`, `bin/ExamineSpec`) is
untouched.

## What works today

### Per-fixture regression coverage

Five committed micro-fixtures plus the pre-existing x86_64
`collatz-x86` exercise every entry point:

| Fixture                          | OS    | Arch      | ObjC | Swift | ARC | Phase-6 spec size |
|----------------------------------|-------|-----------|------|-------|-----|--------------------|
| `collatz-x86` (pre-existing)     | MACOS | AMD64     | n/a  | n/a   | n/a | unchanged          |
| `arm64-macos-collatz`            | MACOS | AARCH64   | 0    | 0     | 0   | 44.3 KB            |
| `arm64-macos-objc-hello.dylib`   | MACOS | AARCH64   | 1 cls / 1 mtd / several pairs | 0 | several | 71.6 KB |
| `arm64-macos-swift-hello`        | MACOS | AARCH64   | 0    | > 0   | ≥ 1 | 86.7 KB            |
| `arm64e-macos-sample`            | MACOS | AARCH64E† | 0    | 0     | 0   | 44.3 KB            |
| `arm64-ios-encrypted-stub`       | IOS†  | —         | —    | —     | —   | throws             |

(†) emitted through `EnumShim` reflection; falls back to the
nearest existing enum when the vendored anvill proto doesn't have
the new value. See README support matrix for the shim fallback table.

### Real-world smoke — FreeOTP iOS app

Observed on the FreeOTP.app arm64 iOS binary (541 KB, not
committed; test harness at
`irene-ghidra/src/test/scala/FreeOtpSmokeTest.scala`, excluded
via `.git/info/exclude`):

| Metric                            | Count       |
|-----------------------------------|-------------|
| Mach-O / iOS platform detection   | ✓ (`IOS`)   |
| arm64e detection                  | ✓ (`false`) |
| FairPlay cryptid detection        | ✓ (`0`)     |
| Chained-fixup detection           | ✓ (`false`) |
| ObjC classes                      | 28          |
| ObjC methods                      | 216         |
| ObjC selref slots                 | 326         |
| `_objc_msgSend` call sites        | 1542        |
| Swift functions (mangled)         | 320         |
| Swift demangled sentinels         | 320 (raw mangled; Ghidra 10.3 has no demangler) |
| Swift async functions             | 0           |
| swiftself / swifterror pins       | 320 / 320 (balanced) |
| `__swift5_*` metadata sections    | 10          |
| ARC call sites (ObjC + Swift)     | 4365        |
| Extractor wall-clock              | < 40 s      |

### Phase-by-phase commit map

| Phase | Commit    | Scope                                                     |
|-------|-----------|-----------------------------------------------------------|
| 0     | `9a15762` | Fixtures + `MachoDetection` scaffolding + phase0 goldens  |
| 1     | `3504892` | AArch64 Darwin CC, platform / arch detection, EnumShim    |
| 3     | `1d24409` | arm64e + FairPlay fail-fast + chained-fixup guard         |
| 4     | `b19b1f4` | Objective-C extraction (classes / methods / selrefs / msgSend / ARC) |
| 5     | `df10ff7` | Swift extraction (functions / demangled / pins / §5 sections / ARC) |
| 6     | `00c55ba` | ARC pair peephole + integration harness + README matrix + this doc |
| 7.1   | pending   | ObjC protocol + category enumeration + new fixture                |
| 7.5   | pending   | Fat / universal binary slicer script                              |
| 7.6   | pending   | dyld shared-cache dylib extractor wrapper                         |

Vendor proto additions (Phase 2) live on isolated branches:
`vendor/anvill@irene3/ios-macho-enums` (submodule) and
`vendor/anvill-ios-macho-enums` (parent, captures the pointer bump).
They have not been merged into `kumarak/test_aarch64`; the
`EnumShim` reflection layer keeps the rest of the branch buildable.

## What is deferred

### Upstream-gated

- **`EnumShim` removal** (plan Phase 6.4). Blocked on the vendor
  proto PR merging upstream and the submodule bump being applied
  to `kumarak/test_aarch64`. Until then the shim stays; runtime
  behaviour is correct via reflection.
- **Real `OS_IOS` / `ARCH_AARCH64E` / `CALLING_CONVENTION_SWIFTCALL`
  / etc. wire bytes** in emitted specs. Today they are shimmed to
  the nearest existing enum value.

### Downstream-gated (remill / anvill C++)

- **arm64e PAC instruction semantics** in remill. The spec
  already tags binaries as arm64e; lifted IR will treat PAC
  instructions as strip until remill lands the semantics. No code
  change required in `irene-ghidra` when that happens.
- **Full end-to-end `bin/Decompile` run** on iOS-scale binaries.
  The existing `anvill.MappingDomain.join` type-constraint solver
  scales super-linearly with function count and currently times
  out on mid-sized iOS apps (~4.5k functions, observed on
  FreeOTP). The Apple extractors themselves are fast; the bottle-
  neck is pre-existing solver code. Phase 6 of this work does not
  address it — it is a self-contained performance problem that
  deserves its own plan.

### Proto-schema-gated (nice-to-have once Phase 2 is merged)

- Promote the sentinel Symbol entries to structured fields on
  `Function` and `Callsite`: `is_objc_method`, `is_swift_function`,
  `is_swift_async`, `demangled_name`, `arc_kind`, `objc_selector`,
  `uses_pac`, `objc_resolved_target`.
- Per-function `uses_pac: bool` on arm64e binaries (scanning each
  function for PAC mnemonics — the detection plumbing is a
  one-pass listing walk; the field is what we need).

### Phase 7 stretch — not done in this session

Three Phase 7 items from the plan remain untouched:

- **7.2 Swift generic specialisation + dynamic replacement tracking.**
  Medium effort; Swift specialised functions get separate mangled
  names (`TA`, `Tc`, etc.) but aren't paired with their generic
  origin in the spec today. Requires more Swift mangling-grammar
  parsing.
- **7.3 Swift async continuation graph.** The biggest Phase 7 item
  by effort. Phase 5 flags async functions via the `YaF` / `YaK`
  mangled suffix and pins `x22`; full async-partial graph
  reconstruction (walking `__swift5_acfuncs`, correlating partials
  through the context pointer, emitting grouping sentinels) is
  deferred. Only worth doing for async-heavy workloads — zero
  payoff on apps that don't use Swift concurrency.
- **7.4 arm64e PAC key / discriminator extraction.** Scan each
  arm64e function for PAC mnemonics and record
  `(instr_addr, key, discriminator)` triples. Gated on remill
  arm64e PAC semantics landing — until then the data has no
  consumer.

### Out of scope (documented for completeness)

- **FairPlay decryption**. irene3 cannot and should not decrypt.
  Detection + fail-fast is sufficient.
- **dyld shared-cache extraction**. The user extracts individual
  dylibs via an external tool (e.g. `dyld_shared_cache_util`)
  before running the extractor.
- **Swift async continuation graph reconstruction**. Metadata
  sections are emitted; higher-level split-frame analysis is a
  separate plan.
- **ObjC category / protocol enumeration**. Classes and methods are
  emitted; categories and protocols would be a natural Phase 7
  stretch.

## Re-running the harness

```
# Unit + integration (gradle)
GHIDRA_INSTALL_DIR=/path/to/amp-ghidra \
JAVA_HOME=/opt/homebrew/opt/openjdk@17 \
./gradlew :irene-ghidra:test

# Integration-only (headless + spec diff)
GHIDRA_INSTALL_DIR=... \
JAVA_HOME=... \
tests/integration/macho/run.sh
```
