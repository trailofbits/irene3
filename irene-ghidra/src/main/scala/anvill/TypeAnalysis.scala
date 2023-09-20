package anvill
import ghidra.program.model.listing.Function as GFunction
import CompleteLifting.given
import MappingDomain.given
import ReachingDefinitions.given
import IdealIntervalDom.given
import anvill.Fixpoint.Solution
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.pcode.PcodeOp

/*
Type analysis joins the results of StackPointsTo and ReachingDefinitions to form the analysis context (NodeContext)
required by type constraint generation.
 */

class SplitContext[R, P](
    val reg_context: RegisterContext[R] with LinearlyExecutable[R],
    val pts_context: PointsToContext[P] with LinearlyExecutable[P]
) extends NodeContext[(R, P)]:
  def execute(cont: (R, P), pc: ghidra.program.model.pcode.PcodeOp): (R, P) =
    (reg_context.execute(cont._1, pc), pts_context.execute(cont._2, pc))

  // Members declared in anvill.PointsToContext
  def pointsTo(
      cont: (R, P),
      vnode: ghidra.program.model.pcode.Varnode,
      sz: anvill.ByteSize
  ): List[anvill.TypeVariableAccess] =
    pts_context.pointsTo(cont._2, vnode, sz)

  // Members declared in anvill.RegisterContext
  def access(
      cont: (R, P),
      vnode: ghidra.program.model.pcode.Varnode
  ): Set[anvill.TypeVariable] =
    reg_context.access(cont._1, vnode)

class TypeAnalysis(val func: GFunction) {
  val cfg: ComputeNodeContext.CFG = ComputeNodeContext.func_to_cfg(func)

  def entries(): Iterable[CfgNode] = cfg.nodes
    .filter(_.incoming.isEmpty)
    .map(x => {
      x.outer
    })

  def analyzePointsTo(): Solution[CfgNode, StackPointsTo.D] = {
    val ent_points_to = StackPointsTo.func_entry_value(func)
    implicit val res: PcodeFixpoint[StackPointsTo.D] =
      StackPointsTo.apply(func.getProgram)
    ComputeNodeContext
      .node_fixpoint[StackPointsTo.D](cfg, entries().map((_, ent_points_to)))
  }

  def analyzeReachingDefs(): Solution[CfgNode, ReachingDefinitions.Dom] = {
    val ent_rdefs = ReachingDefinitions.entry_state(func)
    implicit val reachind_defs: PcodeFixpoint[ReachingDefinitions.Dom] =
      ReachingDefinitions(func.getProgram)
    ComputeNodeContext.node_fixpoint[ReachingDefinitions.Dom](
      cfg,
      entries().map((_, ent_rdefs))
    )
  }

  def mixMapping[K, V1, V2](m1: Map[K, V1], m2: Map[K, V2])(using
      j1: JoinSemiLattice[V1],
      j2: JoinSemiLattice[V2]
  ): Map[K, (V1, V2)] =
    (m1.keysIterator ++ m2.keysIterator)
      .map(k => (k, (m1.getOrElse(k, j1.bot), m2.getOrElse(k, j2.bot))))
      .toMap
      .withDefault(_ => (j1.bot, j2.bot))

  def analyzeWithAddressSetView(addrs: AddressSetView): List[TypeConstraint] = {
    val fix_points_to = analyzePointsTo()
    val reg_analysis = analyzeReachingDefs()

    val mixed: Map[CfgNode, (ReachingDefinitions.Dom, StackPointsTo.D)] =
      mixMapping(reg_analysis, fix_points_to)

    implicit val cont: NodeContext[(ReachingDefinitions.Dom, StackPointsTo.D)] =
      SplitContext(
        ReachingDefsNodeSol(func.getProgram),
        StackPointsToSol(func.getProgram)
      )

    TypeConstraints(func, mixed).produceConstraintsFromAddrRange(addrs)
  }
  def analyze(): List[TypeConstraint] = {
    analyzeWithAddressSetView(func.getBody)
  }
}
