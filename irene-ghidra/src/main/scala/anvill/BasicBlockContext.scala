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
import specification.specification.{Parameter => ParamSpec}
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

  def produceSymvals(
      block_addr: Address,
      additional_displacement: Int
  ): Map[Register, Int] = {

    val regs = gfunc.getProgram.getLanguage.getRegisters.asScala.filter(r =>
      r.isBaseRegister()
    )

    regs
      .map(r => (r, stack_depth_info.getRegDepth(block_addr, r)))
      .filter((_, dpth) => Function.INVALID_STACK_DEPTH_CHANGE != dpth)
      .map((r, dpth) => (r, dpth + additional_displacement))
      .toMap

  }

  def liveness(block_addr: Address): BlockLiveness = {
    liveness_info(block_addr)
  }

  def paramSpecToRegister(p: ParamSpec): Option[Register] = {
    val vs = p.reprVar.get
    if vs.values.length != 1 then { None }
    else {
      val v = vs.values(0)
      v.innerValue.reg.flatMap(r =>
        Option(gfunc.getProgram().getLanguage().getRegister(r.registerName))
      )
    }
  }

  def sdepths_to_filter(sdepths: Map[Register, Int]): ParamSpec => Boolean =
    p => paramSpecToRegister(p).map(r => !sdepths.contains(r)).getOrElse(true)

  def getBlockContext(
      block_addr: Address,
      last_insn_addr: Address
  ): BlockContextSpec = {
    assert(!liveness_info.isEmpty)

    val stack_depths_entry = produceSymvals(block_addr, 0)
    val last_insn_disp = stack_depth_info.getInstructionStackDepthChange(
      gfunc.getProgram().getListing().getInstructionAt(last_insn_addr)
    )
    val stack_depths_exit =
      if last_insn_disp != Function.UNKNOWN_STACK_DEPTH_CHANGE then
        produceSymvals(last_insn_addr, last_insn_disp)
      else Map.empty
    val stack_reg = gfunc.getProgram.getCompilerSpec().getStackPointer()
    val live = this.liveness(block_addr)

    BlockContextSpec(
      stack_depths_entry
        .map((reg, dpth) => {
          ValueMapSpec(
            Some(registerToVariable(reg)),
            Some(ValueDomain(ValueDomain.Inner.StackDisp(dpth)))
          )

        })
        .toSeq,
      live.live_before.filter(sdepths_to_filter(stack_depths_entry)).toSeq,
      live.live_after.filter(sdepths_to_filter(stack_depths_exit)).toSeq
    )
  }
}
