import anvill.macho.MachoDetection
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.base.project.GhidraProject
import ghidra.program.model.listing.Program
import ghidra.test.{AbstractGhidraHeadedIntegrationTest, TestEnv}
import ghidra.util.Msg
import ghidra.util.task.TimeoutTaskMonitor
import org.junit.Assert.{assertFalse, assertTrue}
import org.junit.{After, Before, Test}

import java.io.File
import java.util.concurrent.TimeUnit

class MachoDetectionTest extends AbstractGhidraHeadedIntegrationTest {
  var env: TestEnv = _

  private val machoArm64: File = File(
    getClass.getResource("binaries/arm64-macos-collatz").getFile
  )
  private val machoX86: File = File(
    getClass.getResource("binaries/collatz-x86").getFile
  )
  private val elfArm32: File = File(
    getClass.getResource("binaries/arm-linux-gnueabihf-fibonacci").getFile
  )

  private var machoArm64Prog: Program = _
  private var machoX86Prog: Program = _
  private var elfArm32Prog: Program = _

  private def loadProgram(proj: GhidraProject, file: File): Program = {
    val prog = proj.importProgram(file)
    proj.analyze(prog, true)
    val monitor = TimeoutTaskMonitor.timeoutIn(10, TimeUnit.SECONDS)
    val analysisMgr = AutoAnalysisManager.getAnalysisManager(prog)
    analysisMgr.startAnalysis(monitor)
    analysisMgr.waitForAnalysis(null, monitor)
    prog
  }

  @Before def buildEnv(): Unit = {
    Msg.setErrorLogger(new StderrLogger)
    env = new TestEnv()
    val proj = env.getGhidraProject
    machoArm64Prog = loadProgram(proj, machoArm64)
    machoX86Prog = loadProgram(proj, machoX86)
    elfArm32Prog = loadProgram(proj, elfArm32)
  }

  @After def tearDown(): Unit = env.dispose()

  @Test def machoArm64IsDetected(): Unit =
    assertTrue(
      "arm64-macos-collatz must be detected as Mach-O",
      MachoDetection.isMachO(machoArm64Prog)
    )

  @Test def machoX86IsDetected(): Unit =
    assertTrue(
      "collatz-x86 must be detected as Mach-O",
      MachoDetection.isMachO(machoX86Prog)
    )

  @Test def elfIsNotMacho(): Unit =
    assertFalse(
      "arm-linux-gnueabihf-fibonacci must not be detected as Mach-O",
      MachoDetection.isMachO(elfArm32Prog)
    )
}
