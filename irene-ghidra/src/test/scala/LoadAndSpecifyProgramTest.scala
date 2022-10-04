import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.test.TestEnv
import scala.io.Source
import java.io.File
import java.util.concurrent.TimeUnit
import anvill.ProgramSpecifier
import specification.specification.Arch.ARCH_AMD64
import specification.specification.OS.OS_MACOS

import org.junit.Before
import org.junit.Test
import org.junit.After
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.base.project.GhidraProject
import ghidra.test.AbstractProgramBasedTest
import ghidra.util.Msg
import ghidra.util.ErrorLogger
import ghidra.util.task.TimeoutTaskMonitor
import ghidra.framework.ToolUtils
import ghidra.program.model.listing.Program
import generic.test.AbstractGenericTest
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertFalse

class StderrLogger extends ErrorLogger {

  override def debug(
      orig: Object,
      message: Object,
      exception: Throwable
  ): Unit = System.err.println(orig.toString() + ":" + message)

  override def debug(orig: Object, message: Object): Unit = {
    System.err.println(orig.toString() + ":" + message)
  }

  override def info(orig: Object, message: Object, x$2: Throwable): Unit =
    System.err.println(orig.toString() + ":" + message)

  override def info(orig: Object, message: Object): Unit =
    System.err.println(orig.toString() + ":" + message)

  override def trace(orig: Object, message: Object, x$2: Throwable): Unit =
    System.err.println(orig.toString() + ":" + message)

  override def trace(orig: Object, message: Object): Unit =
    System.err.println(orig.toString() + ":" + message)

  override def warn(orig: Object, message: Object, x$2: Throwable): Unit =
    System.err.println(orig.toString() + ":" + message)

  override def warn(orig: Object, message: Object): Unit =
    System.err.println(orig.toString() + ":" + message)

  override def error(orig: Object, message: Object, x$2: Throwable): Unit =
    System.err.println(orig.toString() + ":" + message)

  override def error(orig: Object, message: Object): Unit =
    System.err.println(orig.toString() + ":" + message)

}

class LoadAndSpecifyProgramTest extends AbstractGhidraHeadlessIntegrationTest { // extends AbstractProgramBasedTest {
  var env: TestEnv = _
  var collatz: Program = _
  var stackArgsX86: Program = _
  var jmpX86: Program = _
  var callX86: Program = _
  var globalsX86: Program = _

  def loadProgram(proj: GhidraProject, resourcePath: String): Program = {
    val file = File(
      getClass.getResource(resourcePath).getFile()
    )

    val prog = proj.importProgram(file)

    proj.analyze(prog, true)

    val monitor = TimeoutTaskMonitor.timeoutIn(10, TimeUnit.SECONDS)
    val analysisMgr = AutoAnalysisManager.getAnalysisManager(prog)
    analysisMgr.scheduleOneTimeAnalysis(
      analysisMgr.getAnalyzer("Decompiler Parameter ID"),
      prog.getMemory()
    )
    analysisMgr.startAnalysis(monitor)
    analysisMgr.waitForAnalysis(null, monitor)

    prog
  }

  @Before def buildenv(): Unit = {
    val logger = StderrLogger()

    Msg.setErrorLogger(logger)
    env = new TestEnv()

    val proj = this.env.getGhidraProject()
    collatz = loadProgram(proj, "binaries/collatz-x86")
    stackArgsX86 = loadProgram(proj, "binaries/stack-args-x86.o")
    jmpX86 = loadProgram(proj, "binaries/jmp-x86.o")
    callX86 = loadProgram(proj, "binaries/call-x86.o")
    globalsX86 = loadProgram(proj, "binaries/globals-x86.o")
  }

  @After def destroyenv(): Unit = {
    env.dispose()
  }

  @Test def collatzX86Tests(): Unit = {
    val spec = ProgramSpecifier.specifyProgram(collatz)
    assertEquals(ARCH_AMD64, spec.arch)
    assertEquals(OS_MACOS, spec.operatingSystem)

    assertEquals(
      "collatz-x86 should have two functions ",
      2,
      spec.functions.length
    )

    assertEquals(
      "collatz-x86 should have six memory ranges",
      6,
      spec.memoryRanges.length
    )
    spec.memoryRanges.foreach(range =>
      assertTrue(
        "Range at address " + range.address
          .toString() + " is neither writeable nor contains data",
        range.isWriteable || range.values.size() > 0
      )
    )

    assertEquals(
      "collatz-x86 should have no global variables",
      0,
      spec.globalVariables.length
    )
  }

  @Test def stackArgsX86Tests(): Unit = {
    val spec = ProgramSpecifier.specifyProgram(stackArgsX86)
    assertEquals(
      "stack-args-x86 should have a single function",
      1,
      spec.functions.length
    )

    val func = spec.functions(0)
    assertEquals(
      "stack-args-x86' function should have two parameters",
      2,
      func.parameters.length
    )

    assertEquals(
      "stack-args-x86 should have a single memory range",
      1,
      spec.memoryRanges.length
    )

    val maybeRetAddr = func.returnAddress
    assertFalse(
      "stack-args-x86' memory range should not be empty",
      maybeRetAddr.isEmpty
    )

    val retAddr = maybeRetAddr.get.innerValue
    assertTrue(
      "stack-args-x86' return address should be stored in memory",
      retAddr.isMem
    )
    val mem = retAddr.mem.get
    assertTrue(
      "stack-args-x86's base address should exist",
      mem.baseReg.nonEmpty
    )
    assertEquals(
      "stack-args-x86' base address should be ESP",
      "ESP",
      mem.baseReg.get
    )
    assertEquals("stack-args-x86' memory offset should be zero", 0, mem.offset)

    assertEquals(
      "stack-args-x86 should have one return",
      1,
      spec.overrides.get.returns.length
    )
  }

  @Test def jmpX86Tests(): Unit = {
    val spec = ProgramSpecifier.specifyProgram(jmpX86)
    assertEquals(
      "jmp-x86 should have a single function",
      1,
      spec.functions.length
    )

    val func = spec.functions(0)
    assertEquals(
      "jmp-x86's function should have two parameters",
      2,
      func.parameters.length
    )

    assertEquals(
      "jmp-x86 should have a single memory range",
      1,
      spec.memoryRanges.length
    )

    val jumps = spec.overrides.get.jumps

    assertEquals("jmp-x86 should have a single jump", 1, jumps.length)
    assertEquals(
      "the jump should be at address 0x1000f",
      0x1000f,
      jumps(0).address
    )
    assertEquals(
      "the jump should have a single target",
      1,
      jumps(0).targets.length
    )
    assertEquals(
      "the jump should target address 0x10013",
      0x10013,
      jumps(0).targets(0).address
    )
    assertFalse("the jump should not stop the lifting process", jumps(0).stop)
  }

  @Test def callX86Tests(): Unit = {
    val spec = ProgramSpecifier.specifyProgram(callX86)
    val calls = spec.overrides.get.calls

    assertEquals("call-x86 should have a single call", 1, calls.length)
    assertEquals(
      "call-x86 should have a call at 0x10015",
      0x10015,
      calls(0).address
    )
    assertFalse("the call should not stop the lifting process", calls(0).stop)
  }

  @Test def globalsX86Tests(): Unit = {
    val spec = ProgramSpecifier.specifyProgram(globalsX86)
    assertEquals(
      "globals-x86 should have three globals",
      3,
      spec.globalVariables.length
    )
  }
}
