package anvill

import ghidra.program.model.address.Address
import ghidra.program.model.block.CodeBlock
import ghidra.program.model.pcode.{PcodeOp, Varnode}
import ghidra.program.model.listing.{
  FlowOverride,
  Instruction,
  Listing,
  Function as GFunction
}
import ghidra.util.Msg
import scalax.collection.generic.{AbstractDiEdge, AnyDiEdge, AnyEdge, Edge}
import scalax.collection.immutable.{Graph, TypedGraphFactory}
import ghidra.program.model.address.AddressFactory
import specification.SpecificationOuterClass.ParameterOrBuilder

import scala.collection.mutable
import scala.jdk.CollectionConverters.IteratorHasAsScala
import scala.collection.mutable.Map as MMap

/*
  Implements utilities for fixed point analysis of Pcode by building a function CFG that respects intra-instruction
control flow. PcodeForwardFixpoint insulates clients from low level graph details.
 */

implicit class ComparablePcodeOp(private val pc: PcodeOp)
    extends PcodeOp(pc.getSeqnum, pc.getOpcode, pc.getInputs, pc.getOutput) {
  override def equals(obj: Any): Boolean =
    obj match {
      case opc: PcodeOp =>
        getSeqnum == opc.getSeqnum && opc.getOpcode == getOpcode
      case _ => false
    }
}

final class CfgEdge(
    src: ComparablePcodeOp,
    val label: CfgEdgeLabel,
    dst: ComparablePcodeOp
) extends AbstractDiEdge[ComparablePcodeOp](src, dst) {
  override def toString: String = {
    s"CfgEdge(${src.getSeqnum}, $label, ${dst.getSeqnum})"
  }
}

sealed trait CfgEdgeLabel
case class GuardLabel(vnode: Varnode, taken: Boolean) extends CfgEdgeLabel
case class PcodeLabel(exec: ComparablePcodeOp) extends CfgEdgeLabel

trait JoinSemiLattice[D] extends PartialOrdering[D] {
  val bot: D

  def join(lhs: D, rhs: D): D
}

trait Problem[D, E] {
  def update_edge(pred: D, e: E): D

  // Step function for widening
  def step(prev: D, next: D, edge: E, curr_step: Long): D = next
}

/*
Produces a solution for a graph with edges
 */
object ForwardEdgeFixpoint {
  type Solution[E, D] = Map[E, D]

  // Forget about edge sensitivity
  def edge_solution_to_node_sol[N, E <: AnyDiEdge[N], D](
      g: Graph[N, E],
      sol: Solution[E, D]
  )(using joinSemiLattice: JoinSemiLattice[D]): Solution[N, D] = {
    g.nodes
      .map(n => {
        (
          n.outer,
          n.incoming.map(sol(_)).fold(joinSemiLattice.bot)(joinSemiLattice.join)
        )
      })
      .toMap
      .withDefault(_ => joinSemiLattice.bot)
  }

  def fixpoint[N, E <: AnyDiEdge[N], D](
      g: Graph[N, E],
      entrypoints: Iterable[(N, D)]
  )(using
      prob: Problem[D, E],
      joinSemiLattice: JoinSemiLattice[D]
  ): Solution[E, D] = {
    val synthetic_preconditions: Map[N, D] = entrypoints.toMap
    val state: MMap[E, D] = MMap.empty.withDefault(_ => joinSemiLattice.bot)
    val ctrs: MMap[E, Long] = MMap.empty.withDefault(_ => 0)
    // TODO(Ian) pq based on RPO
    val worklist: mutable.Queue[N] = mutable.Queue.from(entrypoints.map(_._1))
    while (worklist.nonEmpty) {
      val next = worklist.dequeue()

      val outer = g.get(next)
      val pred =
        synthetic_preconditions.getOrElse(
          next,
          outer.incoming
            .map(state(_))
            .fold(joinSemiLattice.bot)(joinSemiLattice.join)
        )

      for (e <- outer.outgoing) {
        val next_val = prob.update_edge(pred, e)
        val prev_val = state(e)
        if (next_val != prev_val) {
          if (joinSemiLattice.lteq(next_val, prev_val)) {
            println("eq? " + next_val.equals(prev_val))
            println("next:" + next)
            println("pred: " + pred)
            println("nval: " + next_val)
            println("prev_val: " + prev_val)
          }
          assert(
            joinSemiLattice.gt(next_val, prev_val),
            "Transfer functions should be monotonic"
          )
          val curr_step = ctrs(e) + 1
          val widened = prob.step(prev_val, next_val, e, curr_step)
          assert(
            joinSemiLattice.lteq(next_val, widened),
            "Widening should not decrease"
          )
          state.addOne(e, widened)
          ctrs.addOne(e, curr_step)
          worklist.prepend(e.target)

        }
      }
    }

    state.toMap.withDefault(_ => joinSemiLattice.bot)
  }

}

trait PcodeForwardFixpoint[D] {
  def update_guard(vnode: Varnode, taken: Boolean, pred: D): D

  def update_op(op: PcodeOp, pred: D): D

  def step(prev: D, next: D, curr_step: Long): D = next
}

given [D](using
    pcodeAnalysis: PcodeForwardFixpoint[D],
    lat: JoinSemiLattice[D]
): Problem[D, CfgEdge] with
  override def update_edge(pred: D, e: CfgEdge): D =
    e.label match {
      case GuardLabel(vnode, taken) =>
        pcodeAnalysis.update_guard(vnode, taken, pred)
      case PcodeLabel(exec) => pcodeAnalysis.update_op(exec, pred)
    }

  override def step(prev: D, next: D, edge: CfgEdge, curr_step: Long): D =
    pcodeAnalysis.step(prev, next, curr_step)

object ComputeNodeContext {

  type CFG = Graph[PcodeOp, CfgEdge]
  object CFG extends TypedGraphFactory[PcodeOp, CfgEdge]

  def normalControlFlow(op: PcodeOp): Boolean =
    op.getOpcode <= 3 || op.getOpcode >= 11

  def instructionHead(listing: Listing, addr: Address): Option[PcodeOp] =
    Option(listing.getInstructionAt(addr)).flatMap(_.getPcode.headOption)

  def getNextPcodeFallThrough(instruction: Instruction): Option[PcodeOp] =
    Option(instruction.getFallThrough)
      .flatMap(addr =>
        Option(instruction.getProgram.getListing.getInstructionAt(addr))
      )
      .flatMap(insn => insn.getPcode.headOption)

  def getIntraOrInterInstructionFallthrough(
      instruction: Instruction,
      curr_ind: Int
  ): Option[PcodeOp] =
    instruction
      .getPcode()
      .lift(curr_ind + 1)
      .orElse(getNextPcodeFallThrough(instruction))

  def computeJumpTarget(
      listing: Listing,
      addr: AddressFactory,
      vnode: Varnode,
      ops: Array[PcodeOp],
      i: Int
  ): Option[PcodeOp] = if vnode.isConstant then
    ops.lift(i + vnode.getOffset.toInt)
  else
    Option
      .when(vnode.isAddress)(vnode.getOffset)
      .flatMap(off =>
        instructionHead(listing, addr.getDefaultAddressSpace.getAddress(off))
      )

  def createInterestingEdges(
      ops: Array[PcodeOp],
      op: PcodeOp,
      i: Int,
      instruction: Instruction
  ): List[CfgEdge] = {
    val listing = instruction.getProgram.getListing
    val is_overriden_to_return =
      Option(instruction.getFlowOverride).contains(FlowOverride.RETURN)

    def defaultEdge(dst: Option[PcodeOp]): List[CfgEdge] =
      dst.map(CfgEdge(op, PcodeLabel(op), _)).toList

    op.getOpcode match {
      case PcodeOp.CALL | PcodeOp.CALLIND | PcodeOp.BRANCHIND
          if is_overriden_to_return =>
        List()
      case PcodeOp.CALL | PcodeOp.CALLIND =>
        defaultEdge(getNextPcodeFallThrough(instruction))
      case PcodeOp.BRANCHIND =>
        defaultEdge(
          instruction.getFlows.headOption.flatMap(instructionHead(listing, _))
        )

      case PcodeOp.CBRANCH =>
        getIntraOrInterInstructionFallthrough(instruction, i)
          .map(CfgEdge(op, GuardLabel(op.getInput(1), false), _))
          .toList ++
          computeJumpTarget(
            listing,
            instruction.getProgram.getAddressFactory,
            op.getInput(0),
            ops,
            i
          ).map(CfgEdge(op, GuardLabel(op.getInput(1), true), _))
      case PcodeOp.BRANCH =>
        defaultEdge(
          computeJumpTarget(
            listing,
            instruction.getProgram.getAddressFactory,
            op.getInput(0),
            ops,
            i
          )
        )
      case PcodeOp.RETURN =>
        List() // TODO(Ian) we could technically have a control flow override... we should probably,
      // handle these better, same for blr
    }
  }

  def edges(gfunc: GFunction)(instruction: Instruction): List[CfgEdge] = {
    val ops = instruction.getPcode
    val buf = List.newBuilder[CfgEdge]

    for ((op, i) <- ops.zipWithIndex)
      if (normalControlFlow(op)) {
        if (i + 1 < ops.length) {
          buf += CfgEdge(op, PcodeLabel(op), ops(i + 1))
        } else {
          // fallthrough
          val dst = getNextPcodeFallThrough(instruction)
          dst match {
            case None        => Msg.warn(this, "expected fallthrough for pcode")
            case Some(dstop) => buf += CfgEdge(op, PcodeLabel(op), dstop)
          }
        }
      } else {
        buf ++= createInterestingEdges(ops, op, i, instruction)
      }

    buf.result()
  }

  def func_to_cfg(gfunc: GFunction): CFG = {
    CFG.from(
      IteratorHasAsScala(
        gfunc.getProgram.getListing.getInstructions(gfunc.getBody, true)
      ).asScala
        .flatMap(edges(gfunc))
        .toList
    )
  }

  // specialized fixpoint that hides some graph internals. This interface is inspired by cwe_checker and bap graphlib.
  def fixpoint[D](g: CFG, entrypoints: Iterable[(PcodeOp, D)])(using
      PcodeForwardFixpoint[D],
      JoinSemiLattice[D]
  ): ForwardEdgeFixpoint.Solution[CfgEdge, D] =
    ForwardEdgeFixpoint.fixpoint(g, entrypoints)

  def node_fixpoint[D](g: CFG, entrypoints: Iterable[(PcodeOp, D)])(using
      PcodeForwardFixpoint[D],
      JoinSemiLattice[D]
  ): ForwardEdgeFixpoint.Solution[PcodeOp, D] =
    ForwardEdgeFixpoint.edge_solution_to_node_sol(g, fixpoint(g, entrypoints))
}
