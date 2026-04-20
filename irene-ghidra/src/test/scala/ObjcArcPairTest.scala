import anvill.ProgramSpecifier
import anvill.macho.ArcRuntime
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

/** Phase 6.1 — ARC retain-autoreleased-return marker-nop peephole.
 *  Apple ARC emits `bl <callee>; mov x29,x29; bl _objc_retain…` on
 *  arm64 and the analogous `mov ebp,ebp` sequence on x86_64. The
 *  spec extractor must emit a triple sentinel for each detected
 *  pair so the downstream lifter can fuse the retain-autorelease.
 */
class ObjcArcPairTest extends AbstractGhidraHeadedIntegrationTest {
  private var env: TestEnv = _

  private val objcHelloFile: File =
    File(getClass.getResource("binaries/arm64-macos-objc-hello.dylib").getFile)
  private val collatzFile: File =
    File(getClass.getResource("binaries/arm64-macos-collatz").getFile)

  private var objcHelloProg: Program = _
  private var collatzProg: Program = _

  private def loadProgram(proj: GhidraProject, file: File): Program = {
    val prog = proj.importProgram(file)
    proj.analyze(prog, true)
    val monitor = TimeoutTaskMonitor.timeoutIn(60, TimeUnit.SECONDS)
    val mgr = AutoAnalysisManager.getAnalysisManager(prog)
    mgr.startAnalysis(monitor)
    mgr.waitForAnalysis(null, monitor)
    prog
  }

  @Before def buildEnv(): Unit = {
    Msg.setErrorLogger(new StderrLogger)
    env = new TestEnv()
    val proj = env.getGhidraProject
    objcHelloProg = loadProgram(proj, objcHelloFile)
    collatzProg = loadProgram(proj, collatzFile)
  }

  @After def tearDown(): Unit = env.dispose()

  /** The ObjC hello.dylib calls `[NSString stringWithFormat:…]` which
   *  returns an autoreleased NSString — a canonical place for the
   *  marker-nop + retainAutoreleasedReturnValue pair to appear.
   */
  @Test def arcPairsEmittedOnObjcDylib(): Unit = {
    val spec = ProgramSpecifier.specifyProgram(objcHelloProg)
    val pairs = spec.symbols.filter(_.name.startsWith(ArcRuntime.objcArcPairSentinel))
    assertFalse(
      s"Expected at least one __irene_arc_pair_ sentinel on the ObjC " +
        s"dylib; saw only ${spec.symbols.take(30).map(_.name).mkString(", ")}",
      pairs.isEmpty
    )
  }

  /** Plain C (no ARC) must not emit any pair sentinels. */
  @Test def plainArm64HasNoArcPairs(): Unit = {
    val spec = ProgramSpecifier.specifyProgram(collatzProg)
    val pairs = spec.symbols.filter(_.name.startsWith(ArcRuntime.objcArcPairSentinel))
    assertTrue(
      s"Plain C binary must not emit ARC pair sentinels; saw: " +
        pairs.map(_.name).mkString(", "),
      pairs.isEmpty
    )
  }
}
