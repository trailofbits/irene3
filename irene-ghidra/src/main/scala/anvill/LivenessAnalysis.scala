package anvill

import java.util as ju
import scala.collection.mutable
import ghidra.program.model.block.CodeBlock
import ghidra.program.model.lang.Register
import scala.collection.mutable.Stack
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.listing.Instruction
import collection.JavaConverters._

case class BlockLiveness(
    val live_before: Set[Register],
    val live_after: Set[Register]
)

/** Reverse dataflow analysis over the CFG for register liveness
  *
  * @param control_flow_graph
  *   the control flow graph
  * @param func
  *   the function
  */
class LivenessAnalysis(
    val control_flow_graph: Util.CFG,
    val func: ghidra.program.model.listing.Function
) {

  val lang = func.getProgram().getLanguage()

  def gen(op: PcodeOp): Set[Register] = {
    val read_regs = op
      .getInputs()
      .map(vnode =>
        Option(lang.getRegister(vnode.getAddress(), vnode.getSize())).map(reg =>
          reg.getBaseRegister()
        )
      )

    read_regs.flatten.toSet
  }

  // TODO(Ian): Call pcodeops should kill returns
  def kill(op: PcodeOp): Set[Register] = {
    val out = Option(op.getOutput())
    out
      .flatMap(vnode =>
        Option(lang.getRegister(vnode.getAddress(), vnode.getSize()))
      )
      .map(nd => Set.empty + nd)
      .getOrElse(Set.empty)
  }

  def transfer(n: PcodeOp, live_after: Set[Register]): Set[Register] = {
    (live_after -- kill(n)) ++ gen(n)
  }

  def transfer_block(
      blk: CodeBlock,
      live_after: Set[Register]
  ): Set[Register] = {
    // get instructions in reverse then iterate over pcode in reverse
    val insns_reverse: ju.Iterator[Instruction] =
      func.getProgram().getListing().getInstructions(blk, false)
    insns_reverse.asScala.toSeq.foldLeft(live_after)(
      (curr_liveness, curr_insn) =>
        curr_insn
          .getPcode()
          .foldRight(curr_liveness)((pcode, liveness) =>
            transfer(pcode, liveness)
          )
    )
  }

  def collectLiveOnExit(
      n: CodeBlock,
      curr_liveness: scala.collection.Map[CodeBlock, Set[Register]]
  ): Set[Register] = {
    val regs: Seq[Set[Register]] = control_flow_graph
      .get(n)
      .outNeighbors
      .toSeq
      .map(out => curr_liveness.get(out.toOuter).getOrElse(Set.empty))

    regs.fold(Set.empty)((x: Set[Register], y: Set[Register]) => x.union(y))
  }

  def getBlockLiveness(): Map[CodeBlock, BlockLiveness] = {
    val analysisRes = this.analyze()

    analysisRes.toMap.map((blk: CodeBlock, liveness_after: Set[Register]) =>
      (blk, BlockLiveness(transfer_block(blk, liveness_after), liveness_after))
    )
  }

  def analyze(): mutable.Map[CodeBlock, Set[Register]] = {
    val res: mutable.Map[CodeBlock, Set[Register]] = mutable.Map.empty

    val worklist: Stack[CodeBlock] = Stack.from(
      this.control_flow_graph.nodes
        .filter(nd => nd.outNeighbors.isEmpty)
        .map(nd => nd.toOuter)
    )

    while (!worklist.isEmpty) {
      val curr_block = worklist.pop()
      val curr_block_value = res.getOrElse(curr_block, Set.empty)

      val input = collectLiveOnExit(curr_block, res)
      val live_before_block = transfer_block(curr_block, input)
      res.addOne((curr_block, live_before_block))
      if (live_before_block != curr_block_value) {
        for (
          in_neighbor <- this.control_flow_graph.get(curr_block).inNeighbors
        ) {
          worklist.push(in_neighbor.toOuter)
        }
      }
    }

    res
  }

}
