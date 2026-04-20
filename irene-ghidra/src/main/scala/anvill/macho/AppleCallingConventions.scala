package anvill.macho

import ghidra.program.model.lang.CompilerSpec
import ghidra.program.model.listing.Function
import specification.specification.CallingConvention as AnvillCC

/** Detects anvill calling conventions for functions in Mach-O binaries.
 *
 *  Detection order (first match wins):
 *   1. Ghidra's CompilerSpec returns `"swiftcall"` / `"swiftasynccall"` →
 *      use the corresponding Apple CC. (Today Ghidra rarely returns
 *      these; kept for forward compatibility with future cspec files.)
 *   2. Function name is demangled-Swift-looking
 *      (`$s` / `_$s` / `_T0` prefix) → `SWIFTCALL`, or
 *      `SWIFTASYNCCALL` if the mangled suffix ends with `YaF`/`YaK`.
 *      (Phase 5 will do this; kept stubbed here so the detection
 *      surface is complete from Phase 1.)
 *   3. Ghidra classifies the function under the Objective-C namespace
 *      or its name matches `-[...]` / `+[...]` → the *method* uses
 *      plain AArch64 Darwin CC; only *call sites into `_objc_msgSend`*
 *      use the OBJC_MSGSEND CC, which is applied separately in Phase 4.
 *   4. Processor is AArch64 → AArch64 Darwin.
 *   5. Processor is x86 → defer to the existing x86 mapping
 *      (fastcall / stdcall / thiscall / vectorcall / cdecl).
 *   6. Else → UNSPECIFIED.
 *
 *  Swift and Objective-C detection are stubbed behind `enableSwift` and
 *  `enableObjcMsgSend` booleans so Phase 1 can exercise only rules
 *  4–6 without touching the rest. Phases 4 and 5 flip them on.
 */
object AppleCallingConventions:

  /** Runtime feature flags — flipped to `true` in Phases 4/5. */
  @volatile var enableObjcMethod: Boolean = false
  @volatile var enableSwift: Boolean = false

  /** Detect the anvill calling convention for a Mach-O function. */
  def detect(func: Function): AnvillCC =
    val prog = func.getProgram
    val procName = prog.getLanguage.getProcessor.toString.toLowerCase
    val ghidraCc = Option(func.getCallingConvention).map(_.getName).getOrElse("")

    // Rule 1: Ghidra already knows about swiftcall.
    if ghidraCc == "swiftcall" then return EnumShim.ccSwiftcall()
    if ghidraCc == "swiftasynccall" then return EnumShim.ccSwiftasynccall()

    // Rule 2 and 3: Swift / Objective-C name detection. Gated behind
    // feature flags so Phase 1 can exercise the AArch64 Darwin path
    // in isolation.
    if enableSwift && isSwiftFunction(func) then
      return if isSwiftAsync(func) then EnumShim.ccSwiftasynccall()
             else EnumShim.ccSwiftcall()

    // ObjC methods are NOT tagged with OBJC_MSGSEND — the method body
    // itself uses AArch64 Darwin; only call sites into _objc_msgSend
    // carry the OBJC_MSGSEND CC, and those are handled separately.

    // Rule 4: AArch64 → Darwin AAPCS64.
    if procName.contains("aarch64") then return EnumShim.ccAArch64Darwin()

    // Rule 5: defer to existing x86 mapping.
    if procName.contains("x86") then return mapX86(func)

    // Rule 6.
    AnvillCC.CALLING_CONVENTION_UNSPECIFIED

  /** Replicates the original `ProgramSpecifier.getCallingConvention`
   *  x86 branch so the Mach-O x86_64 path is bit-identical to the
   *  pre-Phase-1 behaviour.
   */
  private def mapX86(func: Function): AnvillCC =
    Option(func.getCallingConvention) match
      case None => AnvillCC.CALLING_CONVENTION_UNSPECIFIED
      case Some(cc) =>
        cc.getName match
          case CompilerSpec.CALLING_CONVENTION_cdecl      => AnvillCC.CALLING_CONVENTION_CDECL
          case CompilerSpec.CALLING_CONVENTION_fastcall   => AnvillCC.CALLING_CONVENTION_FASTCALL
          case CompilerSpec.CALLING_CONVENTION_stdcall    => AnvillCC.CALLING_CONVENTION_STDCALL
          case CompilerSpec.CALLING_CONVENTION_thiscall   => AnvillCC.CALLING_CONVENTION_THISCALL
          case CompilerSpec.CALLING_CONVENTION_vectorcall => AnvillCC.CALLING_CONVENTION_VECTORCALL
          case _                                          => AnvillCC.CALLING_CONVENTION_UNSPECIFIED

  private def isSwiftFunction(func: Function): Boolean =
    val n = func.getSymbol.getName
    n.startsWith("$s") || n.startsWith("_$s") || n.startsWith("_T0")

  private def isSwiftAsync(func: Function): Boolean =
    val n = func.getSymbol.getName
    n.endsWith("YaF") || n.endsWith("YaK")
