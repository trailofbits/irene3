package anvill
import ghidra.program.model.listing.Function
import ghidra.program.model.address.Address
import ghidra.app.cmd.function.CallDepthChangeInfo
import collection.JavaConverters._
import ghidra.program.model.lang.Register
import specification.specification.{BlockContext => BlockContextSpec}
import specification.specification.{Register => RegSpec}
import specification.specification.OffsetDomain
import ProgramSpecifier.getRegisterName

class BasicBlockContextProducer(gfunc: Function) {

  val stack_depth_info =
    CallDepthChangeInfo(gfunc, ghidra.util.task.TaskMonitor.DUMMY)

  val liveness_info =
    LivenessAnalysis(Util.getCfgAsGraph(gfunc), gfunc)
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
    liveness_info.get(block_addr).get
  }

  def getBlockContext(block_addr: Address): BlockContextSpec = {
    val stack_depths = produceSymvals(block_addr)
    val stack_reg = gfunc.getProgram.getCompilerSpec().getStackPointer()
    val live = this.liveness_info(block_addr)

    BlockContextSpec(
      stack_depths
        .map((reg, dpth) => {
          OffsetDomain(
            getRegisterName(reg),
            Some(getRegisterName(stack_reg)),
            dpth
          )
        })
        .toSeq,
      live.live_before.toSeq.map(r => RegSpec(getRegisterName(r))),
      live.live_after.toSeq.map(r => RegSpec(getRegisterName(r)))
    )
  }
}
