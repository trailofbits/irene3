import anvill.plugin.anvillgraph.AnvillGraphProvider
import anvill.plugin.anvillgraph.AnvillSlices
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.test.AbstractGhidraHeadedIntegrationTest
import ghidra.test.TestEnv

import collection.JavaConverters.*
import scala.io.Source
import java.io.File
import java.util.concurrent.TimeUnit
import anvill.{BasicBlockSplit, ProgramSpecifier}
import docking.ComponentProvider
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
import ghidra.util.task.{TaskMonitor, TimeoutTaskMonitor}
import ghidra.framework.ToolUtils
import ghidra.program.model.listing.Program
import generic.test.AbstractGenericTest
import ghidra.app.context.ProgramLocationActionContext
import ghidra.app.util.PluginConstants
import ghidra.framework.plugintool.PluginTool
import ghidra.program.model.address.{Address, AddressSetView}
import ghidra.program.model.block.BasicBlockModel
import ghidra.program.util.{ProgramLocation, ProgramSelection}
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertFalse
import specification.specification.CodeBlock
import ghidra.program.model.address.AddressSet

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

class LoadAndSpecifyProgramTest extends AbstractGhidraHeadedIntegrationTest { // extends AbstractProgramBasedTest {
  var env: TestEnv = _
  var collatz: Program = _
  var stackArgsX86: Program = _
  var jmpX86: Program = _
  var callX86: Program = _
  var globalsX86: Program = _
  var satck_args_tool: PluginTool = _

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
    satck_args_tool = env.launchDefaultTool(stackArgsX86)
  }

  @After def destroyenv(): Unit = {
    env.dispose()
  }

  object MockActionContext {
    def apply(
        func: ghidra.program.model.listing.Function,
        addrs: AddressSetView
    ): MockActionContext = {
      val prov =
        satck_args_tool.getComponentProvider(PluginConstants.CODE_BROWSER)
      val prog = func.getProgram

      new MockActionContext(
        prov,
        prog,
        ProgramLocation(prog, addrs.getMinAddress),
        ProgramSelection(addrs),
        ProgramSelection(addrs)
      )
    }
  }
  class MockActionContext(
      prov: ComponentProvider,
      prog: Program,
      loc: ProgramLocation,
      programSelection: ProgramSelection,
      highlight: ProgramSelection
  ) extends ProgramLocationActionContext(
        prov,
        prog,
        loc,
        programSelection,
        highlight
      ) {}

  def runBlockSplitWithSelections(
      func: ghidra.program.model.listing.Function,
      selects: Seq[AddressSetView]
  ): Map[Long, CodeBlock] = {
    val slices = new AnvillSlices
    selects.foreach(addr =>
      AnvillGraphProvider.addSliceToSaveList(
        MockActionContext(func, addr),
        slices
      )
    )

    val model = BasicBlockModel(func.getProgram)
    val fpoints = slices.getSlices(func)
    BasicBlockSplit.splitBlocks(
      func,
      model
        .getCodeBlocksContaining(func.getBody, TaskMonitor.DUMMY)
        .iterator()
        .asScala,
      fpoints.asScala.toSet
    )
  }

  @Test def blockSplitStackArgs(): Unit = {
    val addr_fac = stackArgsX86.getAddressFactory
    val func = stackArgsX86.getFunctionManager.getFunctionAt(
      addr_fac.getAddress("00010000")
    )
    val sel1 =
      AddressSet(addr_fac.getAddress("0010003"), addr_fac.getAddress("0010008"))
    val sel2 =
      AddressSet(addr_fac.getAddress("001000b"), addr_fac.getAddress("001000d"))
    val bmap = runBlockSplitWithSelections(func, Seq(sel1, sel2))
    assertEquals(5, bmap.size)

    assertEquals(6, bmap(0x10003).size)
    assertEquals(3, bmap(0x10000).size)
    assertEquals(2, bmap(0x10009).size)
    assertEquals(3, bmap(0x1000b).size)
    assertEquals(1, bmap(0x1000e).size)
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
      "collatz-x86 should have five memory ranges",
      5,
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
      func.callable.get.parameters.length
    )

    assertEquals(
      "stack-args-x86 should have a single memory range",
      1,
      spec.memoryRanges.length
    )

    val maybeRetAddr = func.callable.get.returnAddress
    assertFalse(
      "stack-args-x86' return addres should not be empty",
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
      func.callable.get.parameters.length
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
