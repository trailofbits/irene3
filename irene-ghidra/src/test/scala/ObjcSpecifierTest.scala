import anvill.ProgramSpecifier
import anvill.macho.{ArcRuntime, ObjcSpecifier}
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.base.project.GhidraProject
import ghidra.program.model.listing.Program
import ghidra.test.{AbstractGhidraHeadedIntegrationTest, TestEnv}
import ghidra.util.Msg
import ghidra.util.task.TimeoutTaskMonitor
import org.junit.Assert.{assertEquals, assertFalse, assertNotNull, assertTrue}
import org.junit.{After, Before, Test}

import java.io.File
import java.util.concurrent.TimeUnit

/** Phase 4 assertions. Every ObjC fact is carried through the spec as
 *  a sentinel Symbol under a well-known prefix (see `ArcRuntime`).
 *  These tests make the same queries that the downstream lifter
 *  would make.
 */
class ObjcSpecifierTest extends AbstractGhidraHeadedIntegrationTest {
  private var env: TestEnv = _

  private val objcHelloFile: File =
    File(getClass.getResource("binaries/arm64-macos-objc-hello.dylib").getFile)
  private val arm64CollatzFile: File =
    File(getClass.getResource("binaries/arm64-macos-collatz").getFile)

  private var objcHelloProg: Program = _
  private var arm64CollatzProg: Program = _

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
    objcHelloProg = loadProgram(proj, objcHelloFile)
    arm64CollatzProg = loadProgram(proj, arm64CollatzFile)
  }

  @After def tearDown(): Unit = env.dispose()

  // ------------------------------------------------------------------
  //  Pattern parser (a small pure unit test — no Ghidra needed)
  // ------------------------------------------------------------------

  @Test def parsesInstanceMethodName(): Unit = {
    val parsed = ObjcSpecifier.parseObjcMethodName("-[Hello greet:]")
    assertEquals(Some(("-", "Hello", "greet:")), parsed)
  }

  @Test def parsesClassMethodName(): Unit = {
    val parsed = ObjcSpecifier.parseObjcMethodName("+[NSString stringWithFormat:]")
    assertEquals(Some(("+", "NSString", "stringWithFormat:")), parsed)
  }

  @Test def rejectsNonObjcName(): Unit = {
    assertEquals(None, ObjcSpecifier.parseObjcMethodName("plainCFunction"))
    assertEquals(None, ObjcSpecifier.parseObjcMethodName("-[no-closing-bracket"))
  }

  // ------------------------------------------------------------------
  //  Integration tests against the ObjC hello.dylib fixture
  // ------------------------------------------------------------------

  /** The `Hello` class must surface as an objc-class sentinel symbol. */
  @Test def helloClassEmittedAsSentinel(): Unit = {
    val spec = ProgramSpecifier.specifyProgram(objcHelloProg)
    val classSymbols = spec.symbols.filter(
      _.name.startsWith(ArcRuntime.objcClassSentinel)
    )
    assertFalse(
      "Expected at least one ObjC class sentinel Symbol",
      classSymbols.isEmpty
    )
    assertTrue(
      s"Expected a sentinel for the 'Hello' class; saw: " +
        classSymbols.map(_.name).mkString(", "),
      classSymbols.exists(_.name.endsWith("Hello"))
    )
  }

  /** The `-[Hello greet:]` method must surface as an objc-method
   *  sentinel symbol pointing at the method's entry address.
   */
  @Test def greetMethodEmittedAsSentinel(): Unit = {
    val spec = ProgramSpecifier.specifyProgram(objcHelloProg)
    val methodSymbols = spec.symbols.filter(
      _.name.startsWith(ArcRuntime.objcMethodSentinel)
    )
    assertFalse(
      "Expected at least one ObjC method sentinel Symbol",
      methodSymbols.isEmpty
    )
    assertTrue(
      s"Expected a sentinel for -[Hello greet:]; saw: " +
        methodSymbols.map(_.name).mkString(", "),
      methodSymbols.exists(s =>
        s.name.contains("[Hello ") && s.name.contains("greet:")
      )
    )
  }

  /** At least one `_objc_msgSend` call-site sentinel must be present
   *  since `-[Hello greet:]` calls `[NSString stringWithFormat:]`.
   */
  @Test def msgSendCallSiteTagged(): Unit = {
    val spec = ProgramSpecifier.specifyProgram(objcHelloProg)
    val msgSendSyms = spec.symbols.filter(
      _.name.startsWith(ArcRuntime.objcMsgSendSentinel)
    )
    assertFalse(
      s"Expected at least one msgSend call-site sentinel in " +
        "arm64-macos-objc-hello.dylib; saw only " +
        spec.symbols.take(30).map(_.name).mkString(", "),
      msgSendSyms.isEmpty
    )
  }

  /** At least one ARC call-site sentinel must be present — ObjC
   *  `-fobjc-arc` code emits `objc_retain`/`objc_release`/
   *  `objc_retainAutoreleasedReturnValue` aggressively.
   */
  @Test def arcCallSiteTagged(): Unit = {
    val spec = ProgramSpecifier.specifyProgram(objcHelloProg)
    val arcSyms = spec.symbols.filter(
      _.name.startsWith(ArcRuntime.objcArcSentinel)
    )
    assertFalse(
      s"Expected at least one ARC call-site sentinel in " +
        "arm64-macos-objc-hello.dylib; saw only " +
        spec.symbols.take(30).map(_.name).mkString(", "),
      arcSyms.isEmpty
    )
  }

  /** Selrefs block exists in the ObjC binary and at least one selref
   *  slot must be emitted.
   */
  @Test def selrefsEmitted(): Unit = {
    val spec = ProgramSpecifier.specifyProgram(objcHelloProg)
    val selrefs = spec.symbols.filter(
      _.name.startsWith(ArcRuntime.objcSelrefSentinel)
    )
    assertFalse(
      "Expected at least one __objc_selrefs sentinel",
      selrefs.isEmpty
    )
  }

  /** Non-ObjC arm64 binaries must not gain any Apple sentinels. This
   *  guards against false positives on plain C code.
   */
  @Test def plainArm64HasNoObjcSentinels(): Unit = {
    val spec = ProgramSpecifier.specifyProgram(arm64CollatzProg)
    val sentinels = spec.symbols.filter(_.name.startsWith(ArcRuntime.sentinelPrefix))
    assertTrue(
      s"Plain C binary must not emit Apple sentinels; saw: " +
        sentinels.map(_.name).mkString(", "),
      sentinels.isEmpty
    )
  }
}
