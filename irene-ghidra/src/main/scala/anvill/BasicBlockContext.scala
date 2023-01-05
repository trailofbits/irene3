package anvill
import ghidra.program.model.listing.Function
import ghidra.program.model.address.Address
import ghidra.app.cmd.function.CallDepthChangeInfo
import collection.JavaConverters._
import ghidra.program.model.lang.Register
import specification.specification.{BlockContext => BlockContextSpec}
import specification.specification.{Register => RegSpec}
import specification.specification.{Value => ValueSpec}
import specification.specification.{Variable => VariableSpec}
import specification.specification.TypeSpec
import specification.specification.{ValueMapping => ValueMapSpec}
import specification.specification.ValueDomain
import specification.specification.OffsetDomain
import ghidra.util.Msg
import ghidra.program.model.lang.Register
import Util.registerToVariable
import specification.specification.HighSymbol
import ghidra.program.model.listing.Variable
import ghidra.program.model.listing.Parameter
import specification.specification.HighLoc
import specification.specification.SymbolMapping
import ghidra.program.model.data.Structure

class BasicBlockContextProducer(gfunc: Function) {

  val aliases: scala.collection.mutable.Map[Long, Structure] =
    scala.collection.mutable.Map.empty

  val stack_depth_info =
    CallDepthChangeInfo(gfunc, ghidra.util.task.TaskMonitor.DUMMY)

  val liveness_info =
    LivenessAnalysis(Util.getCfgAsGraph(gfunc), gfunc, aliases)
      .getBlockLiveness()
      .map((k, v) => (k.getFirstStartAddress(), v))

  def produceSymvals(block_addr: Address): Map[Register, Int] = {

    val regs = gfunc.getProgram.getLanguage.getRegisters.asScala

    regs
      .map(r => (r, stack_depth_info.getRegDepth(block_addr, r)))
      .filter((_, dpth) => Function.INVALID_STACK_DEPTH_CHANGE != dpth)
      .toMap

  }

  def liveness(block_addr: Address): BlockLiveness = {
    liveness_info(block_addr)
  }

  def variableToHighSymbol(v: Variable): HighSymbol = {
    val loc = if (v.isInstanceOf[Parameter]) { HighLoc.HIGH_LOC_PARAM }
    else { HighLoc.HIGH_LOC_PARAM }

    HighSymbol(v.getName, loc)
  }

  def getBlockContext(block_addr: Address): BlockContextSpec = {
    assert(!liveness_info.isEmpty)
    val stack_depths = produceSymvals(block_addr)
    val stack_reg = gfunc.getProgram.getCompilerSpec().getStackPointer()
    val live = this.liveness(block_addr)

    BlockContextSpec(
      stack_depths
        .map((reg, dpth) => {
          ValueMapSpec(
            Some(registerToVariable(reg)),
            Some(ValueDomain(ValueDomain.Inner.StackDisp(dpth)))
          )

        })
        .toSeq,
      live.live_before.toSeq,
      live.live_after.toSeq,
      gfunc
        .getAllVariables()
        .toSeq
        .map(v =>
          SymbolMapping(
            Some(variableToHighSymbol(v)),
            Some(ProgramSpecifier.specifyVariable(v, aliases))
          )
        )
    )
  }
}
