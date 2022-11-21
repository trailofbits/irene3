package anvill
import ghidra.program.model.listing.Function
import ghidra.program.model.address.Address
import ghidra.app.cmd.function.CallDepthChangeInfo
import collection.JavaConverters._
import ghidra.program.model.lang.Register
import specification.specification.{BlockContext => BlockContextSpec}
import specification.specification.OffsetDomain

class BasicBlockContextProducer(gfunc: Function, block_addr: Address) {

  val stack_depth_info =
    CallDepthChangeInfo(gfunc, ghidra.util.task.TaskMonitor.DUMMY)

  def produceSymvals(): Map[Register, Int] = {

    val regs = gfunc.getProgram.getLanguage.getRegisters.asScala

    regs
      .map(r => (r, stack_depth_info.getRegDepth(block_addr, r)))
      .filter((_, dpth) => Function.UNKNOWN_STACK_DEPTH_CHANGE != dpth)
      .toMap

  }

  def getBlockContext(): BlockContextSpec = {
    val stack_depths = produceSymvals()
    val stack_reg = gfunc.getProgram.getCompilerSpec().getStackPointer()

    BlockContextSpec(
      stack_depths
        .map((reg, dpth) => {
          OffsetDomain(reg.getName, Some(stack_reg.getName), dpth)
        })
        .toSeq
    )
  }
}
