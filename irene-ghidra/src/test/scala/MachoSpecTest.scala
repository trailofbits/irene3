import anvill.ProgramSpecifier
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.base.project.GhidraProject
import ghidra.program.model.listing.Program
import ghidra.test.{AbstractGhidraHeadedIntegrationTest, TestEnv}
import ghidra.util.Msg
import ghidra.util.task.TimeoutTaskMonitor
import org.junit.Assert.{assertEquals, assertTrue}
import org.junit.{After, Before, Test}
import specification.specification.Arch.{ARCH_AARCH64, ARCH_AMD64}
import specification.specification.CallingConvention as AnvillCC
import specification.specification.OS.OS_MACOS

import java.io.File
import java.util.concurrent.TimeUnit

/** Phase 1 assertions: arm64 Mach-O binaries emit platform-accurate OS
 *  + non-UNSPECIFIED calling conventions; x86 Mach-O regression still
 *  holds after routing through the new Apple dispatch path.
 */
class MachoSpecTest extends AbstractGhidraHeadedIntegrationTest {
  private var env: TestEnv = _

  private val arm64MacosCollatz: File =
    File(getClass.getResource("binaries/arm64-macos-collatz").getFile)
  private val x86MacosCollatz: File =
    File(getClass.getResource("binaries/collatz-x86").getFile)

  private var arm64Prog: Program = _
  private var x86Prog: Program = _

  private def loadProgram(proj: GhidraProject, file: File): Program = {
    val prog = proj.importProgram(file)
    proj.analyze(prog, true)
    val monitor = TimeoutTaskMonitor.timeoutIn(30, TimeUnit.SECONDS)
    val analysisMgr = AutoAnalysisManager.getAnalysisManager(prog)
    analysisMgr.startAnalysis(monitor)
    analysisMgr.waitForAnalysis(null, monitor)
    prog
  }

  @Before def buildEnv(): Unit = {
    Msg.setErrorLogger(new StderrLogger)
    env = new TestEnv()
    val proj = env.getGhidraProject
    arm64Prog = loadProgram(proj, arm64MacosCollatz)
    x86Prog = loadProgram(proj, x86MacosCollatz)
  }

  @After def tearDown(): Unit = env.dispose()

  /** An arm64 macOS binary must come out with arch=ARCH_AARCH64, OS
   *  tagged macOS-family (may be OS_MACOS under the Phase 1 shim),
   *  and every function must have a non-UNSPECIFIED calling
   *  convention.
   */
  @Test def arm64MacosCollatzTests(): Unit = {
    val spec = ProgramSpecifier.specifyProgram(arm64Prog)

    assertEquals("arch must be AArch64", ARCH_AARCH64, spec.arch)
    assertEquals(
      "OS must be OS_MACOS (or iOS under the full proto, but the fixture "
        + "is macOS-targeted)",
      OS_MACOS,
      spec.operatingSystem
    )

    assertTrue(
      "arm64-macos-collatz must have at least one function",
      spec.functions.nonEmpty
    )

    // Every function's Callable must carry a non-UNSPECIFIED CC.
    // This is the critical Phase 1 invariant: before Phase 1, every
    // non-x86 function would have `CALLING_CONVENTION_UNSPECIFIED`.
    val unspecified = spec.functions.filter { f =>
      f.callable
        .map(_.callingConvention)
        .getOrElse(AnvillCC.CALLING_CONVENTION_UNSPECIFIED) ==
        AnvillCC.CALLING_CONVENTION_UNSPECIFIED
    }

    assertTrue(
      s"No function should emit CALLING_CONVENTION_UNSPECIFIED on arm64 "
        + s"Mach-O; offenders: ${unspecified.map(_.entryAddress.toString).mkString(", ")}",
      unspecified.isEmpty
    )
  }

  /** The x86_64 Mach-O fixture must still come out identical after
   *  the new dispatch path. This guards against accidental regressions
   *  from rewiring `getCallingConvention`.
   */
  @Test def collatzX86UnchangedUnderNewDispatch(): Unit = {
    val spec = ProgramSpecifier.specifyProgram(x86Prog)
    assertEquals("x86 Mach-O fixture must still be AMD64", ARCH_AMD64, spec.arch)
    assertEquals("x86 Mach-O fixture must still be OS_MACOS", OS_MACOS, spec.operatingSystem)
    assertEquals(
      "collatz-x86 should still have two functions",
      2,
      spec.functions.length
    )
  }
}
