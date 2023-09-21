package anvill

import anvill.Util.ProgramAnalysisUtilMixin
import ghidra.program.model.address.Address
import ghidra.program.model.lang.Register
import ghidra.program.model.listing.{
  Instruction,
  Parameter,
  Program,
  Function as GFunction
}
import ghidra.program.model.pcode.{PcodeOp, Varnode}

import scala.jdk.CollectionConverters.*

/*
Super simple and standard reaching definitions.
 */

sealed trait DefiningTerm

case class OpDefiner(pc: ComparablePcodeOp) extends DefiningTerm
case class EntDefiner(reg: Varnode) extends DefiningTerm

object ReachingDefinitions {
  type Dom = MappingDomain[Varnode, Set[DefiningTerm]]

  // Define all regs by their entry value
  def entry_state(f: GFunction): ReachingDefinitions.Dom =
    MappingDomain(
      f.getProgram.getLanguage.getRegisters.asScala
        .map(r => {
          val vnode = Varnode(r.getAddress, r.getNumBytes)
          (vnode, Set(EntDefiner(vnode)))
        })
        .toMap
    )

  given reaching_lat[A]: JoinSemiLattice[Set[A]] with
    override val bot: Set[A] = Set.empty

    override def join(lhs: Set[A], rhs: Set[A]): Set[A] = lhs.union(rhs)

    override def lteq(x: Set[A], y: Set[A]): Boolean = x.subsetOf(y)

    override def tryCompare(x: Set[A], y: Set[A]): Option[Int] =
      if x.equals(y) then Some(0)
      else if x.subsetOf(y) then Some(-1)
      else if y.subsetOf(x) then Some(1)
      else None

  def bot(using lat: JoinSemiLattice[Dom]): Dom = lat.bot

  def join(using lat: JoinSemiLattice[Dom]): (Dom, Dom) => Dom = lat.join
}
class ReachingDefinitions(val prog: Program)
    extends ProgramAnalysisUtilMixin
    with PcodeFixpoint[ReachingDefinitions.Dom] {

  def paramToDefinedRegisters(param: Parameter): Iterator[Register] =
    Option(param.getRegisters)
      .map(_.asScala.iterator)
      .getOrElse(List().iterator)

  def update_guard(
      vnode: ghidra.program.model.pcode.Varnode,
      taken: Boolean,
      pred: ReachingDefinitions.Dom
  ): ReachingDefinitions.Dom = pred

  def update_op(
      op: ghidra.program.model.pcode.PcodeOp,
      pred: ReachingDefinitions.Dom
  ): ReachingDefinitions.Dom =
    (op.getOpcode, Option(op.getOutput)) match {
      case (PcodeOp.BRANCH, _) | (PcodeOp.BRANCHIND, _) => pred
      case (PcodeOp.CALL, _) | (PcodeOp.CALLIND, _) =>
        getUniqueCallTarget(op)
          .flatMap(f => Option(f.getReturn))
          .map(paramToDefinedRegisters)
          .map(def_regs => {
            def_regs
              .map(registerToDefinedVnode)
              .foldLeft(pred)((tot, elem) =>
                tot.updated(elem, Set(OpDefiner(op)))
              )
          })
          .getOrElse(pred)
      // apply abi
      // default case where output is written
      case (_, Some(out)) if out.isRegister || out.isUnique =>
        vnodeToBasRegVnodeOrUnique(out)
          .map(pred.updated(_, Set(OpDefiner(op))))
          .getOrElse(pred)
      case _ => pred
    }
}

class ReachingDefsNodeSol(val prog: Program)
    extends ProgramAnalysisUtilMixin
    with RegisterContext[ReachingDefinitions.Dom]
    with LinearlyExecutable[ReachingDefinitions.Dom] {

  // Members declared in anvill.LinearlyExecutable
  override def execute(
      cont: ReachingDefinitions.Dom,
      pc: ghidra.program.model.pcode.PcodeOp
  ): ReachingDefinitions.Dom =
    ReachingDefinitions(prog).update_op(pc, cont)

  // Members declared in anvill.RegisterContext
  override def access(
      cont: ReachingDefinitions.Dom,
      vnode: ghidra.program.model.pcode.Varnode
  ): Set[TypeVariable] =
    val base_vnode =
      if vnode.isRegister then
        vnodeToBasRegVnodeOrUnique(vnode).getOrElse(vnode)
      else vnode
    cont(base_vnode).map {
      case OpDefiner(pc) => Op.apply(pc)
      case EntDefiner(v) => EntryRegValue.apply(v)
    }
}
