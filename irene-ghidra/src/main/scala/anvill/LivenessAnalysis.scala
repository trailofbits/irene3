package anvill

import java.util as ju
import scala.collection.mutable
import ghidra.program.model.block.CodeBlock
import ghidra.program.model.lang.Register
import scala.collection.mutable.Stack
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.listing.Instruction
import collection.JavaConverters._
import ghidra.app.cmd.function.CallDepthChangeInfo
import specification.specification.{Value => ValueSpec}
import specification.specification.{Register => RegSpec}
import specification.specification.{Variable => VarSpec}
import specification.specification.Value.{InnerValue => ValueInner}
import ghidra.program.model.data.Structure
import Util.registerToVariable

case class BlockLiveness(
    val live_before: Set[VarSpec],
    val live_after: Set[VarSpec]
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
    val func: ghidra.program.model.listing.Function,
    val aliases: scala.collection.mutable.Map[Long, Structure]
) {

  val lang = func.getProgram().getLanguage()

  // TODO(Ian) right now we gen all stack vars for any load
  // We could be missing a var for part of the stack becuase of how ghidra does locals
  // Need to conservatively split the stack, also need a backing alias analysis
  def gen_stack_vars(op: PcodeOp): Set[VarSpec] = {
    if (op.getOpcode() == PcodeOp.LOAD) {
      func
        .getLocalVariables()
        .toSeq
        .flatMap(v =>
          if (v.isStackVariable()) then {
            Seq(ProgramSpecifier.specifyVariable(v, aliases))
          } else {
            Seq.empty
          }
        )
        .toSet
    } else { Set.empty }
  }

  // The safe assumption is we kill nothing
  def kill_stack_vars(op: PcodeOp) = {
    Set.empty
  }

  def gen_registers(op: PcodeOp): Set[VarSpec] = {
    val read_regs = op
      .getInputs()
      .map(vnode =>
        Option(lang.getRegister(vnode.getAddress(), vnode.getSize())).map(reg =>
          reg.getBaseRegister()
        )
      )

    read_regs.flatten
      .map(r => registerToVariable(r))
      .toSet
  }

  // TODO(Ian): Call pcodeops should kill returns
  def kill_registers(op: PcodeOp): Set[VarSpec] = {
    val out = Option(op.getOutput())
    out
      .flatMap(vnode =>
        Option(lang.getRegister(vnode.getAddress(), vnode.getSize()))
      )
      .map(nd => Set(registerToVariable(nd)))
      .getOrElse(Set.empty)
  }

  def gen(op: PcodeOp): Set[VarSpec] = {
    gen_stack_vars(op) ++ gen_registers(op)
  }

  def kill(op: PcodeOp): Set[VarSpec] = {
    kill_registers(op) ++ kill_stack_vars(op)
  }

  def transfer(n: PcodeOp, live_after: Set[VarSpec]): Set[VarSpec] = {
    (live_after -- kill(n)) ++ gen(n)
  }

  def transfer_block(
      blk: CodeBlock,
      live_after: Set[VarSpec]
  ): Set[VarSpec] = {
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
      curr_liveness: scala.collection.Map[CodeBlock, Set[VarSpec]]
  ): Set[VarSpec] = {
    val regs: Seq[Set[VarSpec]] = control_flow_graph
      .get(n)
      .outNeighbors
      .toSeq
      .map(out => curr_liveness.get(out.toOuter).getOrElse(Set.empty))

    regs.fold(Set.empty)((x: Set[VarSpec], y: Set[VarSpec]) => x.union(y))
  }

  def getBlockLiveness(): Map[CodeBlock, BlockLiveness] = {
    val analysisRes = this.analyze()

    analysisRes.toMap.map((blk: CodeBlock, liveness_after: Set[VarSpec]) =>
      (blk, BlockLiveness(transfer_block(blk, liveness_after), liveness_after))
    )
  }

  def analyze(): mutable.Map[CodeBlock, Set[VarSpec]] = {
    val res: mutable.Map[CodeBlock, Set[VarSpec]] = mutable.Map.from(
      this.control_flow_graph.nodes.map(nd => (nd.toOuter, Set.empty))
    )

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
