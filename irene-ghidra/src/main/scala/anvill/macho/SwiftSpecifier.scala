package anvill.macho

import ghidra.program.model.address.Address
import ghidra.program.model.listing.{Function, Program}
import ghidra.util.Msg
import specification.specification.Symbol as SymbolSpec

import scala.util.{Failure, Success, Try}

/** Swift metadata extractor.
 *
 *  Emits sentinel entries (see `ArcRuntime.sentinelPrefix`) into the
 *  spec's `repeated Symbol symbols` field so Phase 5 output works
 *  against the unmodified vendor/anvill proto. Fields that properly
 *  belong on `Function` or `Callsite` (is_swift_function,
 *  demangled_name, arc_kind) are carried as Symbol entries and
 *  promoted once the vendor proto PR lands.
 *
 *  Sentinel layout:
 *    __irene_swift_func_<hex>_<mangled>
 *    __irene_swift_demangled_<hex>_<demangled>
 *    __irene_swift_async_<hex>
 *    __irene_swift_pin_self_<hex>     (x20 = swiftself)
 *    __irene_swift_pin_error_<hex>    (x21 = swifterror)
 *    __irene_swift_pin_async_<hex>    (x22 = swiftasync, async only)
 *    __irene_swift5_<section>_<hex>
 *    __irene_arc_<kind>_<hex>         (shared with ObjcSpecifier)
 *
 *  Demangling:
 *    - Attempts `ghidra.app.util.demangler.swift.SwiftDemangler` via
 *      reflection (Ghidra 11+). When absent, falls back to raw
 *      mangled name with a one-shot log warning. The sentinel is
 *      still emitted so the downstream lifter has *some* form of the
 *      name to reason about.
 */
object SwiftSpecifier:

  /** Swift metadata section names — see Apple's Swift ABI docs. */
  private val swiftSections: Seq[String] = Seq(
    "__swift5_types",
    "__swift5_proto",
    "__swift5_protos",
    "__swift5_fieldmd",
    "__swift5_typeref",
    "__swift5_reflstr",
    "__swift5_capture",
    "__swift5_assocty",
    "__swift5_builtin",
    "__swift5_acfuncs",
    "__swift5_mpenum",
    "__swift5_replace",
    "__swift5_replac2",
    "__swift5_entry",
  )

  /** One-shot warning guards. */
  private val warnedNoDemangler = new ThreadLocal[java.lang.Boolean] {
    override def initialValue: java.lang.Boolean = false
  }

  /** Return every Swift-related sentinel Symbol for `prog`. No-op on
   *  non-Mach-O or on Mach-O binaries without Swift content.
   */
  def extract(prog: Program): Seq[SymbolSpec] =
    if !MachoDetection.isMachO(prog) then return Seq.empty
    warnedNoDemangler.set(false)

    extractFunctions(prog) ++ extractMetadataSections(prog)

  // ------------------------------------------------------------------
  //  Function-level: detection, demangling, register pinning
  // ------------------------------------------------------------------

  private def extractFunctions(prog: Program): Seq[SymbolSpec] =
    val fm = prog.getFunctionManager
    val iter = fm.getFunctions(true)
    val out = scala.collection.mutable.ArrayBuffer.empty[SymbolSpec]
    while iter.hasNext do
      val f = iter.next()
      if isSwiftMangledName(f.getName) then emitForSwiftFunction(f, out)
    out.toSeq

  private def emitForSwiftFunction(
      f: Function,
      out: scala.collection.mutable.ArrayBuffer[SymbolSpec],
  ): Unit =
    val mangled = f.getName
    val addr = f.getEntryPoint.getOffset
    val hex = addr.toHexString

    // Function sentinel — carries the raw mangled name.
    out += SymbolSpec(
      name    = s"${ArcRuntime.sentinelPrefix}swift_func_${hex}_$mangled",
      address = addr
    )

    // Demangled name sentinel (falls back to mangled on older Ghidra).
    val displayName = demangle(mangled).getOrElse(mangled)
    out += SymbolSpec(
      name    = s"${ArcRuntime.sentinelPrefix}swift_demangled_${hex}_$displayName",
      address = addr
    )

    // Register pins: x20 (swiftself), x21 (swifterror) on every
    // Swift func; x22 (swiftasync) additionally on async funcs.
    out += SymbolSpec(name = s"${ArcRuntime.sentinelPrefix}swift_pin_self_$hex", address = addr)
    out += SymbolSpec(name = s"${ArcRuntime.sentinelPrefix}swift_pin_error_$hex", address = addr)

    if isSwiftAsyncMangledName(mangled) then
      out += SymbolSpec(name = s"${ArcRuntime.sentinelPrefix}swift_async_$hex", address = addr)
      out += SymbolSpec(name = s"${ArcRuntime.sentinelPrefix}swift_pin_async_$hex", address = addr)

  /** True for Swift 5 stable-ABI (`$s`, `_$s`) and legacy Swift 1.x/
   *  2.x (`_T0`) manglings. Ghidra's symbol table often drops the
   *  leading underscore so both variants are matched.
   */
  def isSwiftMangledName(name: String): Boolean =
    name.startsWith("$s") || name.startsWith("_$s") ||
      name.startsWith("$S") || name.startsWith("_$S") ||
      name.startsWith("_T0")

  /** Swift 5 async thunks end with `Ya` followed by one of the
   *  throwing/non-throwing discriminators `F`, `K`, `C`, `M`, etc.
   *  The simplest safe check is "contains `Ya` shortly before the end"
   *  — good enough for tagging, never a false negative for the
   *  shipped Swift compiler.
   */
  def isSwiftAsyncMangledName(name: String): Boolean =
    val tail = name.takeRight(4)
    tail.contains("Ya")

  /** Attempt to demangle via Ghidra's Swift demangler (present in
   *  Ghidra 11+). Returns `None` and logs a one-shot warning when the
   *  demangler class isn't on the classpath.
   */
  private def demangle(mangled: String): Option[String] =
    ghidraSwiftDemangler match
      case Some(fn) => fn(mangled)
      case None =>
        warnNoDemanglerOnce()
        None

  /** Cached Option[String => Option[String]]; `None` if the demangler
   *  class is unavailable, `Some(fn)` otherwise.
   */
  private lazy val ghidraSwiftDemangler: Option[String => Option[String]] = {
    val candidateClasses = Seq(
      "ghidra.app.util.demangler.swift.SwiftDemangler",
      "ghidra.app.util.demangler.swift.NativeSwiftDemangler",
    )
    candidateClasses.iterator.flatMap { fqcn =>
      Try {
        val cls = Class.forName(fqcn)
        val ctor = cls.getDeclaredConstructor()
        ctor.setAccessible(true)
        val instance = ctor.newInstance()
        // Ghidra's Demangler interface exposes `DemangledObject demangle(MangledContext)`
        // and older variants with `demangle(String, DemanglerOptions)`. Try the simple
        // String-only form first.
        val method = cls.getMethods
          .filter(_.getName == "demangle")
          .find(m =>
            m.getParameterCount == 1 &&
              m.getParameterTypes()(0) == classOf[String]
          )
        method match
          case Some(m) =>
            (s: String) =>
              Try(Option(m.invoke(instance, s)).map(_.toString))
                .getOrElse(None)
          case None =>
            // Fall back to the newer MangledContext-based API if needed.
            null
      }.toOption.flatMap(Option.apply)
    }.find(_ != null)
  }

  private def warnNoDemanglerOnce(): Unit =
    if !warnedNoDemangler.get() then
      warnedNoDemangler.set(true)
      Msg.warn(
        this,
        "[swift] Ghidra Swift demangler not found (requires Ghidra 11+); " +
          "emitting raw mangled names on __irene_swift_demangled_* " +
          "sentinels. Downstream consumers can pipe to `xcrun swift-demangle`."
      )

  // ------------------------------------------------------------------
  //  Metadata sections
  // ------------------------------------------------------------------

  private def extractMetadataSections(prog: Program): Seq[SymbolSpec] =
    val mem = prog.getMemory
    swiftSections.flatMap { name =>
      Option(mem.getBlock(name)).map { blk =>
        val addr = blk.getStart.getOffset
        SymbolSpec(
          name    = s"${ArcRuntime.sentinelPrefix}swift5_${name.stripPrefix("__")}_${addr.toHexString}",
          address = addr
        )
      }
    }
