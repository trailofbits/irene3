import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.app.plugin.processors.sleigh.SleighLanguage
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyDefaultContext
import ghidra.app.plugin.assembler.Assemblers
import ghidra.program.model.mem.ByteMemBufferImpl
import ghidra.program.model.lang.InstructionPrototype
import ghidra.app.util.PseudoInstruction
import ghidra.app.plugin.assembler.Assembler
import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider
import org.junit.Before
import org.junit.Test
import org.junit.After
import ghidra.program.model.lang.LanguageID
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertFalse
import anvill.ProgramSpecifier
import anvill.ProgramSpecifier.ControlFlowOverride
import ghidra.util.Msg

class ControlFlowSpecInsnTest extends AbstractGhidraHeadlessIntegrationTest {
  val DEFAULT_ADDR: Long = 0x40000000L
  var archLang: SleighLanguage = _
  var context: AssemblyDefaultContext = _
  var assembler: Assembler = _

  @Before def buildenv(): Unit = {
    val provider: SleighLanguageProvider = SleighLanguageProvider()
    archLang = provider
      .getLanguage(LanguageID("ARM:LE:32:v8"))
      .asInstanceOf[SleighLanguage]
    context = AssemblyDefaultContext(archLang)
    assembler = Assemblers.getAssembler(archLang)

    val logger = StderrLogger()

    Msg.setErrorLogger(logger)
  }

  protected def disassemble(
      addr: Long,
      ins: Array[Byte],
      ctx: Array[Byte]
  ): PseudoInstruction = {
    val at = this.archLang.getDefaultSpace().getAddress(addr)
    context.setContextRegister(ctx)
    val buf = ByteMemBufferImpl(at, ins, archLang.isBigEndian())
    val prot: InstructionPrototype = archLang.parse(buf, context, false)
    PseudoInstruction(at, prot, buf, context)
  }

  protected def assembleInsn(assembly: String): PseudoInstruction = {
    disassemble(
      DEFAULT_ADDR,
      assembler.assembleLine(
        archLang.getDefaultSpace().getAddress(DEFAULT_ADDR),
        assembly
      ),
      context.getDefault().getVals()
    )
  }

  def specifyInsnWithoutProgramContext =
    ProgramSpecifier.controlFlowOverridesForInstruction(
      _,
      curr_addr => DEFAULT_ADDR + 2 == curr_addr.getOffset(),
      _ => None,
      identity
    )

  @Test
  def testConditionalIndirectCall() = {
    val insn = assembleInsn("blxgt r1")
    assertTrue(insn.getFlowType().isCall())
    assertTrue(insn.getFlowType().isConditional())
    assertTrue(insn.getFlowType().hasFallthrough())
    assertFalse(insn.getFlowType().isTerminal())

    val spec_result = specifyInsnWithoutProgramContext(insn)
    assertTrue(spec_result.isDefined)

    // Assert is call
    assertEquals(1, spec_result.get.ordinal)

    val ControlFlowOverride.SCall(call) = spec_result.get

    assertTrue("Call should have a return", call.returnAddress.isDefined)
  }
}
