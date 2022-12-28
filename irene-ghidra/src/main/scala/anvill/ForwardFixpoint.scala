package anvill

import ghidra.program.model.block.CodeBlock
import collection.mutable
import scala.math.PartiallyOrdered
import scala.collection.mutable.Stack
import ghidra.program.model.pcode.PcodeOp
import java.util as ju
import ghidra.program.model.listing.Instruction
import collection.JavaConverters._

trait PcodeOpTransferFunction[A]:
  def execute_block_entrance(
      func: ghidra.program.model.listing.Function,
      curr_blk: CodeBlock,
      prev: A
  ): A

  def execute_pcode(
      f: ghidra.program.model.listing.Function,
      pc: PcodeOp,
      curr: A
  ): A

  def step(
      f: ghidra.program.model.listing.Function,
      i: Int,
      updating_blk: CodeBlock,
      prev: A,
      next: A
  ): A

class PcodeTransferToBlockTransferAdapter[A](
    val pcode_transfer: PcodeOpTransferFunction[A]
) extends BlockTransferFunction[A] {

  override def execute_block(
      func: ghidra.program.model.listing.Function,
      src_blk: CodeBlock,
      dst_blk: CodeBlock,
      prev_domain_value: A
  ): A = {
    val start_val =
      pcode_transfer.execute_block_entrance(func, src_blk, prev_domain_value)
    val insns_reverse: ju.Iterator[Instruction] =
      func.getProgram().getListing().getInstructions(src_blk, true)
    insns_reverse.asScala
      .flatMap(insn => insn.getPcode().toSeq)
      .foldLeft(start_val)((v, pc) => pcode_transfer.execute_pcode(func, pc, v))
  }

  override def step(
      func: ghidra.program.model.listing.Function,
      i: Int,
      updating_blk: CodeBlock,
      prev: A,
      next: A
  ): A =
    pcode_transfer.step(func, i, updating_blk, prev, next)
}

trait BlockTransferFunction[A]:
  def execute_block(
      func: ghidra.program.model.listing.Function,
      src_blk: CodeBlock,
      dst_blk: CodeBlock,
      prev_domain_value: A
  ): A
  def step(
      func: ghidra.program.model.listing.Function,
      i: Int,
      updating_blk: CodeBlock,
      prev: A,
      next: A
  ): A

trait JoinSemiLatice[A] extends PartialOrdering[A]:
  def join(lhs: A, rhs: A): A
  val bot: A

class ForwardIntraproceduralFixpoint[A](
    val control_flow_graph: Util.CFG,
    val transfer_function: BlockTransferFunction[A],
    val lattice: JoinSemiLatice[A],
    val func: ghidra.program.model.listing.Function
) {

  def analyze(): Map[CodeBlock, A] = {
    // Stores the domain value and how many times it has been updated
    val res: mutable.Map[CodeBlock, (A, Int)] = mutable.Map.from(
      this.control_flow_graph.nodes.map(nd => (nd.toOuter, (lattice.bot, 0)))
    )

    val worklist: Stack[(CodeBlock, CodeBlock)] = Stack.from(
      this.control_flow_graph.edges.toSeq.map(e =>
        (e.source.toOuter, e.target.toOuter)
      )
    )

    while (!worklist.isEmpty) {
      val (src, dst) = worklist.pop()
      val (curr_dom, _) = res.getOrElseUpdate(src, (lattice.bot, 0))
      val (dst_dom, dst_ctr) = res.getOrElseUpdate(src, (lattice.bot, 0))

      val next_val = transfer_function.execute_block(func, src, dst, curr_dom)
      if (!(lattice.lteq(next_val, dst_dom))) {
        val widened_val =
          transfer_function.step(this.func, dst_ctr, dst, dst_dom, next_val)
        res.update(dst, (lattice.join(dst_dom, widened_val), dst_ctr + 1))
      }

      for (
        e <- this.control_flow_graph
          .get(dst)
          .edges
          .toSeq
          .map(e => (e.source.toOuter, e.target.toOuter))
      ) {
        worklist.push(e)
      }
    }

    res.view.mapValues((dom, _) => dom).toMap
  }
}
