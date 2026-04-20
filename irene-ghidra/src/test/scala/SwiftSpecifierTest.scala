import anvill.ProgramSpecifier
import anvill.macho.{ArcRuntime, SwiftSpecifier}
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.base.project.GhidraProject
import ghidra.program.model.listing.Program
import ghidra.test.{AbstractGhidraHeadedIntegrationTest, TestEnv}
import ghidra.util.Msg
import ghidra.util.task.TimeoutTaskMonitor
import org.junit.Assert.{assertEquals, assertFalse, assertTrue}
import org.junit.{After, Before, Test}

import java.io.File
import java.util.concurrent.TimeUnit

/** Phase 5 assertions. Swift facts (per-function, ARC, metadata
 *  sections, register pins) are carried through the spec as
 *  sentinel Symbols under `__irene_swift*` / `__irene_arc_swift_*`
 *  prefixes (see `ArcRuntime`).
 */
class SwiftSpecifierTest extends AbstractGhidraHeadedIntegrationTest {
  private var env: TestEnv = _

  private val swiftHelloFile: File =
    File(getClass.getResource("binaries/arm64-macos-swift-hello").getFile)
  private val collatzFile: File =
    File(getClass.getResource("binaries/arm64-macos-collatz").getFile)

  private var swiftProg: Program = _
  private var collatzProg: Program = _

  private def loadProgram(proj: GhidraProject, file: File): Program = {
    val prog = proj.importProgram(file)
    proj.analyze(prog, true)
    val monitor = TimeoutTaskMonitor.timeoutIn(60, TimeUnit.SECONDS)
    val analysisMgr = AutoAnalysisManager.getAnalysisManager(prog)
    analysisMgr.startAnalysis(monitor)
    analysisMgr.waitForAnalysis(null, monitor)
    prog
  }

  @Before def buildEnv(): Unit = {
    Msg.setErrorLogger(new StderrLogger)
    env = new TestEnv()
    val proj = env.getGhidraProject
    swiftProg = loadProgram(proj, swiftHelloFile)
    collatzProg = loadProgram(proj, collatzFile)
  }

  @After def tearDown(): Unit = env.dispose()

  // ------------------------------------------------------------------
  //  Pure name-classifier unit tests (no Ghidra needed)
  // ------------------------------------------------------------------

  @Test def recognisesStableMangledNames(): Unit = {
    assertTrue(SwiftSpecifier.isSwiftMangledName("_$s4main5greetyS2SF"))
    assertTrue(SwiftSpecifier.isSwiftMangledName("$s4main5greetyS2SF"))
    assertTrue(SwiftSpecifier.isSwiftMangledName("_T0_legacy_mangle"))
    assertFalse(SwiftSpecifier.isSwiftMangledName("_objc_msgSend"))
    assertFalse(SwiftSpecifier.isSwiftMangledName("collatz"))
  }

  @Test def recognisesAsyncManglingSuffix(): Unit = {
    assertTrue(SwiftSpecifier.isSwiftAsyncMangledName("_$s4main3fooyyYaF"))
    assertTrue(SwiftSpecifier.isSwiftAsyncMangledName("_$s4main3fooyyYaK"))
    assertFalse(SwiftSpecifier.isSwiftAsyncMangledName("_$s4main5greetyS2SF"))
  }

  // ------------------------------------------------------------------
  //  Integration tests against the Swift fixture
  // ------------------------------------------------------------------

  /** At least one Swift function (the top-level `greet`) must surface
   *  as an `__irene_swift_func_*` sentinel.
   */
  @Test def greetEmittedAsSwiftFunction(): Unit = {
    val spec = ProgramSpecifier.specifyProgram(swiftProg)
    val funcSentinels = spec.symbols.filter(
      _.name.startsWith(s"${ArcRuntime.sentinelPrefix}swift_func_")
    )
    assertFalse(
      "Expected at least one __irene_swift_func_* sentinel",
      funcSentinels.isEmpty
    )
    assertTrue(
      s"Expected a sentinel whose mangled suffix contains 'greet'; " +
        s"saw: ${funcSentinels.map(_.name).mkString(", ")}",
      funcSentinels.exists(_.name.contains("greet"))
    )
  }

  /** Each Swift function must have a demangled-name sentinel alongside
   *  its function sentinel. On Ghidra without a Swift demangler (this
   *  amp-ghidra build) the sentinel carries the raw mangled name —
   *  the invariant is simply "sentinel exists and is non-empty".
   */
  @Test def greetHasDemangledNameSentinel(): Unit = {
    val spec = ProgramSpecifier.specifyProgram(swiftProg)
    val demangled = spec.symbols.filter(
      _.name.startsWith(s"${ArcRuntime.sentinelPrefix}swift_demangled_")
    )
    assertFalse(
      "Expected at least one __irene_swift_demangled_* sentinel",
      demangled.isEmpty
    )
    // The sentinel name format is __irene_swift_demangled_<hex>_<name>.
    // Check the trailing <name> part is non-empty.
    assertTrue(
      "Expected demangled-name sentinels to carry a non-empty name",
      demangled.forall { s =>
        val suffix = s.name.stripPrefix(s"${ArcRuntime.sentinelPrefix}swift_demangled_")
        val idx = suffix.indexOf('_')
        idx >= 0 && suffix.substring(idx + 1).nonEmpty
      }
    )
  }

  /** Every Swift function must emit swiftself (x20) and swifterror
   *  (x21) register-pin sentinels at its entry address.
   */
  @Test def swiftFunctionsHavePinSentinels(): Unit = {
    val spec = ProgramSpecifier.specifyProgram(swiftProg)
    val selfPins = spec.symbols.count(
      _.name.startsWith(s"${ArcRuntime.sentinelPrefix}swift_pin_self_")
    )
    val errorPins = spec.symbols.count(
      _.name.startsWith(s"${ArcRuntime.sentinelPrefix}swift_pin_error_")
    )
    assertTrue(
      s"Expected >= 1 swiftself pin sentinel, got $selfPins",
      selfPins >= 1
    )
    assertEquals(
      "Every swiftself pin must be paired with a swifterror pin",
      selfPins,
      errorPins
    )
  }

  /** `__swift5_types` and `__swift5_reflstr` (plus whatever else the
   *  Swift compiler emitted) must surface as metadata-section
   *  sentinels. Swift hello.swift produces at least `__swift5_types`.
   */
  @Test def swiftMetadataSectionsEmitted(): Unit = {
    val spec = ProgramSpecifier.specifyProgram(swiftProg)
    val metaSentinels = spec.symbols.filter(
      _.name.startsWith(s"${ArcRuntime.sentinelPrefix}swift5_")
    )
    assertFalse(
      "Expected at least one __irene_swift5_* metadata sentinel",
      metaSentinels.isEmpty
    )
    assertTrue(
      s"Expected a sentinel for __swift5_types; saw: " +
        metaSentinels.map(_.name).mkString(", "),
      metaSentinels.exists(_.name.contains("swift5_swift5_types"))
    )
  }

  /** `_swift_release` / `_swift_allocObject` are imported by the
   *  Swift fixture — their call sites must be tagged via the shared
   *  ARC sentinel channel.
   */
  @Test def swiftArcCallSitesTagged(): Unit = {
    val spec = ProgramSpecifier.specifyProgram(swiftProg)
    val arcSentinels = spec.symbols.filter(
      _.name.startsWith(ArcRuntime.objcArcSentinel)
    )
    assertFalse(
      s"Expected at least one ARC sentinel on the Swift fixture; " +
        s"saw only ${spec.symbols.take(40).map(_.name).mkString(", ")}",
      arcSentinels.isEmpty
    )
    // At least one of them must correspond to a Swift runtime call.
    val swiftArcTags = ArcRuntime.swiftArcSymbols.values.toSet
    assertTrue(
      "Expected at least one swift_* ARC sentinel (swift_retain / " +
        "swift_release / swift_allocObject / etc.); got: " +
        arcSentinels.map(_.name).mkString(", "),
      arcSentinels.exists { s =>
        swiftArcTags.exists(tag => s.name.contains(s"arc_$tag"))
      }
    )
  }

  /** Plain C / non-Swift binaries must not get any `__irene_swift*`
   *  sentinels. Guards against false positives on arm64 C code.
   */
  @Test def plainArm64HasNoSwiftSentinels(): Unit = {
    val spec = ProgramSpecifier.specifyProgram(collatzProg)
    val swiftSentinels = spec.symbols.filter(
      s => s.name.startsWith(s"${ArcRuntime.sentinelPrefix}swift")
    )
    assertTrue(
      s"Plain C binary must not emit Swift sentinels; saw: " +
        swiftSentinels.map(_.name).mkString(", "),
      swiftSentinels.isEmpty
    )
  }
}
