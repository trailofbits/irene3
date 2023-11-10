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
import scala.collection.Traversable
import scala.collection.mutable
import scala.jdk.CollectionConverters.IteratorHasAsScala
import scala.collection.mutable.Map as MMap

/*
  Implements utilities for fixed point analysis of Pcode by building a function CFG that respects intra-instruction
control flow. PcodeForwardFixpoint insulates clients from low level graph details.
 */

sealed trait CfgNode {

  def getAddress: Address =
    this match {
      case InstructionEntry(insn) => insn.getAddress
      case x: ComparablePcodeOp   => x.getSeqnum.getTarget
    }
  override def toString: String =
    this match {
      case InstructionEntry(insn) => insn.toString
      case op: ComparablePcodeOp  => op.getSeqnum.toString
    }
}

case class InstructionEntry(insn: Instruction) extends CfgNode

implicit class ComparablePcodeOp(private val pc: PcodeOp)
    extends PcodeOp(pc.getSeqnum, pc.getOpcode, pc.getInputs, pc.getOutput)
    with CfgNode {
  override def equals(obj: Any): Boolean =
    obj match {
      case opc: PcodeOp =>
        getSeqnum == opc.getSeqnum && opc.getOpcode == getOpcode
      case _ => false
    }
}

final class CfgEdge(
    src: CfgNode,
    val label: CfgEdgeLabel,
    dst: CfgNode
) extends AbstractDiEdge[CfgNode](src, dst) {

  override def toString: String = {
    s"CfgEdge($src, $label, $dst)"
  }
}

sealed trait CfgEdgeLabel
case class GuardLabel(vnode: Varnode, taken: Boolean) extends CfgEdgeLabel
case class PcodeLabel(exec: ComparablePcodeOp) extends CfgEdgeLabel

case object NopLabel extends CfgEdgeLabel

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
object Fixpoint {
  type Solution[E, D] = Map[E, D]

  // Forget about edge sensitivity
  def edge_solution_to_node_sol[N, E <: AnyDiEdge[N], D](
      g: Graph[N, E],
      sol: Solution[E, D],
      ent_vals: Iterable[(N, D)],
      traversal: FixpointTraversal[N, E]
  )(using joinSemiLattice: JoinSemiLattice[D]): Solution[N, D] = {
    val eval_lookups = Map.from(ent_vals)
    g.nodes
      .map(n => {
        val v = traversal
          .prev_edges(n)
          .map(sol(_))
          .fold(eval_lookups.getOrElse(n, joinSemiLattice.bot))(
            joinSemiLattice.join
          )
        (
          n.outer,
          v
        )
      })
      .toMap
      .withDefault(_ => joinSemiLattice.bot)
  }

  def fixpoint[N, E <: AnyDiEdge[N], D](
      g: Graph[N, E],
      entrypoints: Iterable[(N, D)],
      traversal: FixpointTraversal[N, E]
  )(using
      prob: Problem[D, E],
      joinSemiLattice: JoinSemiLattice[D]
  ): Solution[E, D] = {
    val synthetic_preconditions: Map[N, D] = entrypoints.toMap
    val state: MMap[E, D] = MMap.empty.withDefault(_ => joinSemiLattice.bot)
    val ctrs: MMap[E, Long] = MMap.empty.withDefault(_ => 0)
    // TODO(Ian) pq based on RPO
    implicit val scoped: Ordering[N] = traversal
    val worklist: mutable.PriorityQueue[N] =
      mutable.PriorityQueue.from(entrypoints.map((n, _) => n))

    while (worklist.nonEmpty) {
      val next = worklist.dequeue()

      val outer = g.get(next)
      val pred =
        synthetic_preconditions.getOrElse(
          next,
          traversal
            .prev_edges(outer)
            .map(state(_))
            .fold(joinSemiLattice.bot)(joinSemiLattice.join)
        )

      for (e <- traversal.next_edges(outer)) {
        val next_val = prob.update_edge(pred, e)
        val prev_val = state(e)
        if (next_val != prev_val) {

          val curr_step = ctrs(e) + 1
          val widened = prob.step(prev_val, next_val, e, curr_step)
          assert(
            joinSemiLattice.lteq(next_val, widened),
            "Widening should not decrease"
          )

          if (!joinSemiLattice.lteq(prev_val, widened)) {
            Msg.debug(this, "eq? " + widened.equals(prev_val))
            Msg.debug(this, "next:" + next)
            Msg.debug(this, "pred: " + pred)
            Msg.debug(this, "nval: " + widened)
            Msg.debug(this, "prev_val: " + prev_val)
          }
          assert(
            joinSemiLattice.lteq(prev_val, widened),
            "Transfer functions should be monotonic"
          )

          state.addOne(e, widened)
          ctrs.addOne(e, curr_step)

          worklist += traversal.next_node(e)
        }
      }
    }
    state.toMap.withDefault(_ => joinSemiLattice.bot)
  }

}

trait PcodeFixpoint[D] {
  def update_guard(vnode: Varnode, taken: Boolean, pred: D): D

  def update_op(op: PcodeOp, pred: D): D

  def step(prev: D, next: D, curr_step: Long): D = next
}

given [D](using
    pcodeAnalysis: PcodeFixpoint[D],
    lat: JoinSemiLattice[D]
): Problem[D, CfgEdge] with
  override def update_edge(pred: D, e: CfgEdge): D =
    e.label match {
      case NopLabel => pred
      case GuardLabel(vnode, taken) =>
        pcodeAnalysis.update_guard(vnode, taken, pred)
      case PcodeLabel(exec) => pcodeAnalysis.update_op(exec, pred)
    }

  override def step(prev: D, next: D, edge: CfgEdge, curr_step: Long): D =
    pcodeAnalysis.step(prev, next, curr_step)

abstract class FixpointTraversal[N, E <: AnyDiEdge[N]](g: Graph[N, E])
    extends Ordering[N] {
  val priority: Map[N, Int] = ComputeNodeContext.postorder_traversal(g)

  val default: Int

  def get_priority(x: N): Int =
    priority.getOrElse(x, default)

  def next_node(e: E): N

  def next_edges(n: Graph[N, E]#NodeT): Set[E]

  def prev_edges(n: Graph[N, E]#NodeT): Set[E]
}

class ForwardFixpointTraversal[N, E <: AnyDiEdge[N]](
    g: Graph[N, E]
) extends FixpointTraversal[N, E](g) {

  val default: Int = Int.MinValue

  override def compare(x: N, y: N): Int =
    get_priority(x).compare(get_priority(y))

  override def next_node(e: E): N = e.target

  override def next_edges(n: Graph[N, E]#NodeT): Set[E] =
    n.outgoing.map(_.outer)

  override def prev_edges(n: Graph[N, E]#NodeT): Set[E] =
    n.incoming.map(_.outer)
}

class ReverseFixpointTraversal[N, E <: AnyDiEdge[N]](
    g: Graph[N, E]
) extends FixpointTraversal[N, E](g) {

  val default: Int = Int.MaxValue

  override def compare(x: N, y: N): Int =
    // we want the lowest elements first
    -get_priority(x).compare(get_priority(y))

  override def next_node(e: E): N = e.source

  override def next_edges(n: Graph[N, E]#NodeT): Set[E] =
    n.incoming.map(_.outer)

  override def prev_edges(n: Graph[N, E]#NodeT): Set[E] =
    n.outgoing.map(_.outer)
}

object ComputeNodeContext {

  def postorder_traversal[N, E <: AnyDiEdge[N]](
      g: Graph[N, E]
  ): Map[N, Int] = {
    val roots = g.nodes.filter(n => n.incoming.isEmpty)
    val seen: mutable.Set[N] = mutable.Set.empty
    val ordering_buf = List.newBuilder[N]

    roots.foreach(r => {
      g.outerNodeDownUpTraverser(r)
        .foreach((down, node) => {
          if (!down && !seen.contains(node)) {
            seen += node
            ordering_buf += node
          }
        })
    })

    ordering_buf.result().zipWithIndex.toMap
  }

  type CFG = Graph[CfgNode, CfgEdge]

  object CFG extends TypedGraphFactory[CfgNode, CfgEdge]

  def normalControlFlow(op: PcodeOp): Boolean =
    op.getOpcode <= 3 || op.getOpcode >= 11

  def instructionHead(listing: Listing, addr: Address): Option[CfgNode] =
    Option(listing.getInstructionAt(addr)).map(InstructionEntry.apply)

  def getFallThroughInstructionNode(instruction: Instruction): Option[CfgNode] =
    Option(instruction.getFallThrough)
      .flatMap(addr =>
        Option(instruction.getProgram.getListing.getInstructionAt(addr))
          .map(InstructionEntry.apply)
      )

  def getIntraOrInterInstructionFallthrough(
      instruction: Instruction,
      curr_ind: Int
  ): Option[CfgNode] =
    instruction
      .getPcode()
      .lift(curr_ind + 1)
      .map(op => anvill.ComparablePcodeOp(op))
      .orElse(getFallThroughInstructionNode(instruction))

  def computeJumpTarget(
      listing: Listing,
      addr: AddressFactory,
      vnode: Varnode,
      ops: Array[PcodeOp],
      i: Int
  ): Option[CfgNode] = if vnode.isConstant then
    ops.lift(i + vnode.getOffset.toInt).map(op => anvill.ComparablePcodeOp(op))
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

    def defaultEdge(dst: Option[CfgNode]): List[CfgEdge] =
      dst.map(CfgEdge(op, PcodeLabel(op), _)).toList

    op.getOpcode match {
      case PcodeOp.CALL | PcodeOp.CALLIND | PcodeOp.CALLOTHER |
          PcodeOp.BRANCHIND if is_overriden_to_return =>
        List()
      case PcodeOp.CALL | PcodeOp.CALLIND | PcodeOp.CALLOTHER =>
        defaultEdge(getFallThroughInstructionNode(instruction))
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
      case default =>
        throw RuntimeException(
          "Unhandled pcode op: " + default + " at address " + instruction
            .getAddress()
        )
    }
  }

  def edges(gfunc: GFunction)(instruction: Instruction): List[CfgEdge] = {
    val ops = instruction.getPcode
    val buf = List.newBuilder[CfgEdge]

    val hd = InstructionEntry(instruction)
    // The head of an instruction entry marks the analysis values at entry to an instruction.
    // We assume instructions are single entry, multi exit.
    // The instruction head has an edge to the first op if it exists or the next instruction's head
    // if no ops exist. This allows a nop to connect to another nop then to some op at the end.
    // getFallThroughInstructionNode returns the instruction head for the next instruction if it exists.
    val ent_edge = ops
      .lift(0)
      .map(ComparablePcodeOp.apply)
      .orElse(getFallThroughInstructionNode(instruction))
      .map((op: CfgNode) => CfgEdge(hd, NopLabel, op))
    ent_edge.foreach(e => {
      buf += e
    })

    for ((op, i) <- ops.zipWithIndex)
      if (normalControlFlow(op)) {
        if (i + 1 < ops.length) {
          buf += CfgEdge(op, PcodeLabel(op), ops(i + 1))
        } else {
          // fallthrough
          val dst = getFallThroughInstructionNode(instruction)
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
    val init_cfg = CFG.from(
      IteratorHasAsScala(
        gfunc.getProgram.getListing.getInstructions(gfunc.getBody, true)
      ).asScala
        .filter(!_.isInDelaySlot())
        .flatMap(edges(gfunc))
        .toList
    )

    val bod = gfunc.getBody
    val reachable_from_entry: CfgNode => Boolean = Option(gfunc.getEntryPoint)
      .flatMap(a => Option(gfunc.getProgram.getListing.getInstructionAt(a)))
      .map(InstructionEntry)
      .map(st_node => init_cfg.outerNodeTraverser(init_cfg.get(st_node)).toSet)
      .map(s => e => s.contains(e))
      .getOrElse(_ => true)

    init_cfg.filter(nd => {
      bod.contains(nd.getAddress) && reachable_from_entry(nd)
    })
  }

  // specialized fixpoint that hides some graph internals. This interface is inspired by cwe_checker and bap graphlib.
  def fixpoint[D](g: CFG, entrypoints: Iterable[(CfgNode, D)])(using
      PcodeFixpoint[D],
      JoinSemiLattice[D]
  ): Fixpoint.Solution[CfgEdge, D] =
    Fixpoint.fixpoint(
      g,
      entrypoints,
      new ForwardFixpointTraversal[CfgNode, CfgEdge](
        g
      )
    )

  def node_fixpoint[D](g: CFG, entrypoints: Iterable[(CfgNode, D)])(using
      PcodeFixpoint[D],
      JoinSemiLattice[D]
  ): Fixpoint.Solution[CfgNode, D] =
    Fixpoint.edge_solution_to_node_sol(
      g,
      fixpoint(g, entrypoints),
      entrypoints,
      new ForwardFixpointTraversal[CfgNode, CfgEdge](
        g
      )
    )

  def reverse_fixpoint[D](
      g: CFG,
      entrypoints: Iterable[(CfgNode, D)]
  )(using
      PcodeFixpoint[D],
      JoinSemiLattice[D]
  ): Fixpoint.Solution[CfgEdge, D] =
    Fixpoint.fixpoint(
      g,
      entrypoints,
      new ReverseFixpointTraversal[CfgNode, CfgEdge](
        g
      )
    )

  def reverse_node_fixpoint[D](
      g: CFG,
      entrypoints: Iterable[(CfgNode, D)]
  )(using
      PcodeFixpoint[D],
      JoinSemiLattice[D]
  ): Fixpoint.Solution[CfgNode, D] =
    Fixpoint.edge_solution_to_node_sol(
      g,
      reverse_fixpoint(g, entrypoints),
      entrypoints,
      new ReverseFixpointTraversal[CfgNode, CfgEdge](
        g
      )
    )
}
