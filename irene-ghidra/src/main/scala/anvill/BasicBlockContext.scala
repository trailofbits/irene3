package anvill
import ghidra.program.model.listing.Function
import ghidra.program.model.address.Address
import ghidra.app.cmd.function.CallDepthChangeInfo
import collection.JavaConverters._
import ghidra.program.model.lang.Register
import specification.specification.{BlockContext => BlockContextSpec}
import specification.specification.OffsetDomain
import ProgramSpecifier.getRegisterName

class BasicBlockContextProducer(gfunc: Function, block_addr: Address) {

  val stack_depth_info =
    CallDepthChangeInfo(gfunc, ghidra.util.task.TaskMonitor.DUMMY)

  def produceSymvals(): Map[Register, Int] = {

    val regs = gfunc.getProgram.getLanguage.getRegisters.asScala

    regs
      .map(r => (r, stack_depth_info.getRegDepth(block_addr, r)))
      .filter((_, dpth) => Function.INVALID_STACK_DEPTH_CHANGE != dpth)
      .toMap

  }

  def getBlockContext(): BlockContextSpec = {
    val stack_depths = produceSymvals()
    val stack_reg = gfunc.getProgram.getCompilerSpec().getStackPointer()

    BlockContextSpec(
      stack_depths
        .map((reg, dpth) => {
          OffsetDomain(
            getRegisterName(reg),
            Some(getRegisterName(stack_reg)),
            dpth
          )
        })
        .toSeq
    )
  }
}
