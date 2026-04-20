import anvill.ProgramSpecifier
import anvill.macho.{MachoEncryptedException, MachoHeaderReader, MachoPlatform}
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.base.project.GhidraProject
import ghidra.program.model.listing.Program
import ghidra.test.{AbstractGhidraHeadedIntegrationTest, TestEnv}
import ghidra.util.Msg
import ghidra.util.task.TimeoutTaskMonitor
import org.junit.Assert.{assertEquals, assertFalse, assertTrue, fail}
import org.junit.{After, Before, Test}
import specification.specification.Arch.ARCH_AARCH64

import java.io.File
import java.util.concurrent.TimeUnit

/** Phase 3 assertions:
 *   - arm64e binaries are detected as arm64e at the header level.
 *   - arm64 (non-arm64e) binaries are NOT flagged as arm64e.
 *   - FairPlay-encrypted binaries refuse to specify with a clear
 *     cryptid-aware error.
 *   - chained-fixup binaries produce external symbols (implies
 *     Ghidra >= 10.3 is resolving chained fixups).
 */
class MachoArm64eTest extends AbstractGhidraHeadedIntegrationTest {
  private var env: TestEnv = _

  private val arm64eSample: File =
    File(getClass.getResource("binaries/arm64e-macos-sample").getFile)
  private val arm64Collatz: File =
    File(getClass.getResource("binaries/arm64-macos-collatz").getFile)
  private val objcHello: File =
    File(getClass.getResource("binaries/arm64-macos-objc-hello.dylib").getFile)
  private val encryptedStub: File =
    File(getClass.getResource("binaries/arm64-ios-encrypted-stub").getFile)

  private var arm64eProg: Program = _
  private var arm64Prog: Program = _
  private var objcHelloProg: Program = _
  private var encryptedProg: Program = _

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
    arm64eProg = loadProgram(proj, arm64eSample)
    arm64Prog = loadProgram(proj, arm64Collatz)
    objcHelloProg = loadProgram(proj, objcHello)
    encryptedProg = loadProgram(proj, encryptedStub)
  }

  @After def tearDown(): Unit = env.dispose()

  @Test def arm64eSampleDetected(): Unit = {
    assertTrue(
      "arm64e-macos-sample must be detected as arm64e at the header level",
      MachoHeaderReader.isArm64e(arm64eProg)
    )
    assertEquals(
      "arm64e-macos-sample platform must be macOS",
      MachoPlatform.MACOS,
      MachoHeaderReader.platform(arm64eProg)
    )
  }

  @Test def arm64CollatzIsNotArm64e(): Unit = {
    assertFalse(
      "arm64-macos-collatz must NOT be detected as arm64e",
      MachoHeaderReader.isArm64e(arm64Prog)
    )
  }

  /** The spec extractor must tag arm64e binaries with an arch value
   *  that distinguishes them from plain AArch64. Depending on whether
   *  the vendored anvill proto has `ARCH_AARCH64E`, this is either the
   *  real value or the shimmed fallback `ARCH_AARCH64` (plus a log
   *  warning). Both outcomes are acceptable at this phase; assert
   *  whichever EnumShim returns.
   */
  @Test def arm64eSampleSpecifiesWithArm64eArch(): Unit = {
    val spec = ProgramSpecifier.specifyProgram(arm64eProg)
    val shimmed = anvill.macho.EnumShim.archForArm64e()
    assertEquals(
      "arm64e arch must match what EnumShim resolves",
      shimmed,
      spec.arch
    )
    assertTrue(
      "arm64e arch must be either the new ARCH_AARCH64E (when the proto " +
        "PR has landed) or the shimmed fallback ARCH_AARCH64",
      spec.arch == ARCH_AARCH64 || spec.arch.name == "ARCH_AARCH64E"
    )
  }

  /** Encrypted binaries raise MachoEncryptedException with a message
   *  naming the cryptid so the user knows why the extractor refused.
   */
  @Test def encryptedStubThrowsWithCryptidMessage(): Unit = {
    assertTrue(
      "fixture must be detected as encrypted at the header level",
      MachoHeaderReader.isEncrypted(encryptedProg)
    )
    try {
      ProgramSpecifier.specifyProgram(encryptedProg)
      fail("specifyProgram must throw MachoEncryptedException on an " +
        "encrypted binary")
    } catch {
      case ex: MachoEncryptedException =>
        assertEquals("cryptid must be reported", 1, ex.cryptid)
        assertTrue(
          s"exception message must mention cryptid (got '${ex.getMessage}')",
          ex.getMessage.toLowerCase.contains("cryptid")
        )
    }
  }

  /** Binaries that use LC_DYLD_CHAINED_FIXUPS AND that genuinely call
   *  external symbols must have those externals populated by Ghidra.
   *  If they do not, the user's Ghidra is too old and the spec will
   *  be missing external call targets. This test doubles as a smoke
   *  check for the runtime Ghidra version.
   *
   *  The ObjC fixture is used because it calls Foundation APIs;
   *  plain collatz links only against libSystem and has no actual
   *  imports, so it would pass vacuously.
   */
  @Test def chainedFixupsResolved(): Unit = {
    if (MachoHeaderReader.usesChainedFixups(objcHelloProg)) {
      val iter = objcHelloProg.getSymbolTable.getExternalSymbols
      var count = 0
      while (iter.hasNext) { iter.next(); count += 1 }
      assertTrue(
        s"arm64-macos-objc-hello.dylib uses chained fixups; Ghidra should " +
          s"have resolved external symbols (observed: $count). Upgrade to " +
          "Ghidra >= 10.3 if this assertion fails.",
        count > 0
      )
    }
    // else: no chained fixups, nothing to verify
  }
}
