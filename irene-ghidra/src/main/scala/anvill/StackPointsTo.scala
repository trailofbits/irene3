package anvill

import anvill.Util.ProgramAnalysisUtilMixin
import ghidra.program.model.lang.Register
import ghidra.program.model.listing.{Program, Function as GFunction}
import ghidra.program.model.pcode.{PcodeOp, Varnode}
import cats.syntax.all.*
import cats.{Applicative, Monad}
import anvill.CompleteLifting
import anvill.IdealIntervalDom.given
import anvill.MappingDomain.given

import scala.jdk.CollectionConverters.*
import anvill.CompleteLifting.given
import anvill.StackPointsTo.D
import ghidra.program.model.pcode

/*
Implements some very simple register affine relation tracking wrt to
initial register values. Abstract values are either represented by an interval
or a base register (for the initial undefined value) + an interval. This domain allows basic tracking of stack accesses
by collecting all loads/stores that reference a value that is a displacement from the initial value of the stack pointer
 */

sealed trait ARAValue {
  val maybe_dval: Option[IdealIntervalDom.IntervalDomValue]
}
case class Const(domval: IdealIntervalDom.IntervalDomValue) extends ARAValue {
  val maybe_dval: Option[IdealIntervalDom.IntervalDomValue] = Some(domval)
}
case class RegDisp(vnode: Varnode, domval: IdealIntervalDom.IntervalDomValue)
    extends ARAValue {
  val maybe_dval: Option[IdealIntervalDom.IntervalDomValue] = Some(domval)
}

case object Bot extends ARAValue {
  val maybe_dval: Option[IdealIntervalDom.IntervalDomValue] = None
}

object ARADom {
  type D = CompleteLifting[ARAValue]

  given (using
      wd: Widen[IdealIntervalDom.IntervalDomValue]
  ): WidenCompletedDom[ARAValue] with
    override def step(
        prev: ARAValue,
        curr: ARAValue,
        step: Long
    ): CompleteLifting[ARAValue] =
      (prev, curr) match {
        case (Const(x), Const(y)) =>
          Elem(Const(wd.step(x, y, step)))
        case (RegDisp(v1, i1), RegDisp(v2, i2)) if v1 == v2 =>
          Elem(RegDisp(v1, wd.step(i1, i2, step)))
        case (Bot, cv) => Elem(cv)
        case (cv, Bot) => Elem(cv)
        case _         => Top()
      }
}

object ARAValue {
  given (using
      ji: JoinSemiLattice[IdealIntervalDom.IntervalDomValue]
  ): JoinSemiLattice[CompleteLifting[ARAValue]] with
    override val bot: CompleteLifting[ARAValue] = {
      Elem(Bot)
    }

    override def join(
        lhs: CompleteLifting[ARAValue],
        rhs: CompleteLifting[ARAValue]
    ): CompleteLifting[ARAValue] =
      (lhs, rhs).flatMapN((l, r) => {
        (l, r) match {
          case (Bot, o)             => Elem(o)
          case (o, Bot)             => Elem(o)
          case (Const(x), Const(y)) => Elem(Const(ji.join(x, y)))
          case (RegDisp(v1, x), RegDisp(v2, y)) if v1 == v2 =>
            Elem(RegDisp(v1, ji.join(x, y)))
          case _ => Top()
        }
      })

    override def lteq(
        x: CompleteLifting[ARAValue],
        y: CompleteLifting[ARAValue]
    ): Boolean =
      (x, y) match {
        case (_, Top()) => true
        case (Top(), _) => false
        case (Elem(e1), Elem(e2)) =>
          (e1, e2) match {
            case (Bot, _)             => true
            case (_, Bot)             => false
            case (Const(x), Const(y)) => ji.lteq(x, y)
            case (RegDisp(v1, x), RegDisp(v2, y)) if v1.equals(v2) =>
              ji.lteq(x, y)
            case _ =>
              false // TODO(Ian): Intelij says this case is unreachable???? it shouldnt be because of the guard up above what gives?
          }
      }

    override def tryCompare(
        x: CompleteLifting[ARAValue],
        y: CompleteLifting[ARAValue]
    ): Option[Int] =
      val leq = lteq(x, y)
      val geq = lteq(y, x)
      if leq && geq then Some(1)
      else if leq then Some(-1)
      else if geq then Some(1)
      else None
}

/*
  Tracks affine relations between the abstract stack and registers, values in memory are opaque
  which is usually ok for our purposes except when it isnt. We do also do some constant propagation to try to capture
  Tvars for globals. Heap locations are pretty much certain to fail, anything stashed somewhere is also certain to fail
 */

case class AnnotatedDomainObject[D](d: D, bytesize: Int)

trait MachineEval[D] {
  def machine_eval(opc: Int, inputs: List[AnnotatedDomainObject[D]]): D
}

given opt_to_lift[T]: Conversion[Option[T], CompleteLifting[T]] with
  override def apply(x: Option[T]): CompleteLifting[T] =
    x match {
      case None    => Top()
      case Some(x) => Elem(x)
    }

given lift_to_op[T]: Conversion[CompleteLifting[T], Option[T]] with
  override def apply(x: CompleteLifting[T]): Option[T] =
    x match {
      case Top()   => None
      case Elem(x) => Some(x)
    }

case class RelativizedExpr(
    unique_base: Option[Varnode],
    operands: List[AnnotatedDomainObject[IdealIntervalDom.IntervalDomValue]]
)
object ARAExprEval {

  def regFromARA(v: ARAValue): Option[Varnode] = v match {
    case Const(_)          => None
    case RegDisp(vnode, _) => Some(vnode)
    case Bot               => None
  }

  def relativeExprs(
      flist: List[Option[AnnotatedDomainObject[ARAValue]]]
  ): Option[RelativizedExpr] =
    def f(
        working: RelativizedExpr,
        elem: Option[AnnotatedDomainObject[ARAValue]]
    ): Option[RelativizedExpr] =
      for {
        e <- elem
        dval <- e.d.maybe_dval
        new_reg <- Some(regFromARA(e.d))
        r <- Some(working.unique_base.orElse(new_reg))
        if working.unique_base.isEmpty || new_reg.isEmpty
      } yield RelativizedExpr(
        r,
        working.operands ++ List(AnnotatedDomainObject(dval, e.bytesize))
      )
    flist.foldLeftM(RelativizedExpr(None, List()))(f)

  def evalConstants(
      opc: Int,
      vs: List[AnnotatedDomainObject[IdealIntervalDom.IntervalDomValue]]
  ): IdealIntervalDom.IntervalDomValue =
    IdealIntegerTransformer.machine_transform.machine_eval(opc, vs)
  def eval(
      opc: Int,
      inputs: List[AnnotatedDomainObject[ARADom.D]]
  ): ARADom.D = {
    val flattened: List[CompleteLifting[AnnotatedDomainObject[ARAValue]]] =
      inputs.map(x => x.d.map(AnnotatedDomainObject(_, x.bytesize)))
    val rel: CompleteLifting[RelativizedExpr] = relativeExprs(
      flattened.map(lift_to_op(_))
    )
    rel.flatMap((r: RelativizedExpr) => {
      r.unique_base match {
        case Some(rbase)
            if opc == PcodeOp.INT_ADD || opc == PcodeOp.COPY || opc == PcodeOp.INT_SUB =>
          Elem(RegDisp(rbase, evalConstants(opc, r.operands)))
        case None    => Elem(Const(evalConstants(opc, r.operands)))
        case Some(_) => Top()
      }
    })
  }
}

object StackPointsTo {
  type D = CompleteLifting[MappingDomain[Varnode, ARADom.D]]
  import ARADom.given

  def apply(prog: Program): StackPointsTo = {
    new StackPointsTo(prog)
  }

  /// Get an initial stack domain where all registers are mapped to their entry values
  def func_entry_value(f: GFunction): StackPointsTo.D = {
    Elem(
      MappingDomain(
        f.getProgram.getLanguage.getRegisters.asScala
          .map(r => Varnode(r.getAddress, r.getNumBytes))
          .map(v => {
            (v, Elem(RegDisp(v, Elem(IntRange(0, 0)))))
          })
          .toMap
      )
    )
  }
}

trait Widen[D] {
  def step(prev: D, curr: D, curr_step: Long): D
}

class StackPointsTo(val prog: Program)(using wd: Widen[D])
    extends ProgramAnalysisUtilMixin
    with PcodeFixpoint[StackPointsTo.D] {

  override def step(
      prev: StackPointsTo.D,
      next: StackPointsTo.D,
      curr_step: Long
  ): StackPointsTo.D = wd.step(prev, next, curr_step)

  override def update_guard(
      vnode: ghidra.program.model.pcode.Varnode,
      taken: Boolean,
      pred: StackPointsTo.D
  ): StackPointsTo.D = pred

  def writeRegister(
      d: StackPointsTo.D,
      r: Varnode,
      v: ARADom.D
  ): StackPointsTo.D = d.map(m => {
    m.updated(r, v)
  })

  def evalExpr(pc: PcodeOp, cont: StackPointsTo.D): ARADom.D =
    for {
      mp <- cont
      x <- Elem(
        pc.getInputs
          .map(v =>
            AnnotatedDomainObject(
              if v.isConstant then const(v.getOffset) else mp(v),
              v.getSize
            )
          )
          .toList
      )
      evaled <- ARAExprEval.eval(pc.getOpcode, x)
    } yield evaled

  def const(it: BigInt): ARADom.D = Elem(Const(Elem(IntRange(it, it))))

  def mask(byte_size: Int): BigInt = {
    BigInt(2).pow(byte_size * 8) - 1
  }
  def merge(
      prev_dom: ARADom.D,
      curr_dom: ARADom.D,
      prev_size_bytes: Int,
      curr_size_bytes: Int
  ): ARADom.D =
    val size_inc = prev_size_bytes - curr_size_bytes
    if size_inc <= 0 then curr_dom
    else
      val root = ARAExprEval.eval(
        PcodeOp.INT_XOR,
        List(
          AnnotatedDomainObject(prev_dom, prev_size_bytes),
          AnnotatedDomainObject(const(mask(curr_size_bytes)), prev_size_bytes)
        )
      )
      val zext_new = ARAExprEval.eval(
        PcodeOp.INT_ZEXT,
        List(AnnotatedDomainObject(curr_dom, curr_size_bytes))
      )
      ARAExprEval.eval(
        PcodeOp.INT_OR,
        List(
          AnnotatedDomainObject(zext_new, prev_size_bytes),
          AnnotatedDomainObject(root, prev_size_bytes)
        )
      )

  def assignIntoReg(
      varnode: Varnode,
      dom: ARADom.D,
      d: MappingDomain[Varnode, ARADom.D]
  ): MappingDomain[Varnode, ARADom.D] =
    val tgt = vnodeToBasRegVnodeOrUnique(varnode)
    tgt match
      case Some(breg) =>
        val cv = d(breg)
        d.updated(breg, merge(cv, dom, breg.getSize, varnode.getSize))
      case None => d

  override def update_op(op: PcodeOp, pred: StackPointsTo.D): StackPointsTo.D =

    val res: StackPointsTo.D = op.getOpcode match {
      case PcodeOp.CALL =>
        val f: CompleteLifting[GFunction] = opt_to_lift(
          getUniqueFlow(op).flatMap(f =>
            Option(prog.getFunctionManager.getFunctionAt(f))
          )
        )
        f.flatMap(f => {
          f.getCallingConvention.getLikelyTrash.toList
            .flatMap(rv => vnodeToBasRegVnodeOrUnique(rv))
            .foldLeft(pred)((tot, r) => writeRegister(tot, r, Top()))
        })
      case PcodeOp.BRANCH | PcodeOp.BRANCHIND => pred
      case _ if Option(op.getOutput).isDefined =>
        pred.map(assignIntoReg(op.getOutput, evalExpr(op, pred), _))
      case _ => pred
    }

    res
}
class StackPointsToSol(val prog: Program)
    extends ProgramAnalysisUtilMixin
    with PointsToContext[StackPointsTo.D]
    with LinearlyExecutable[StackPointsTo.D] {
  // Members declared in anvill.LinearlyExecutable
  def execute(
      cont: anvill.StackPointsTo.D,
      pc: ghidra.program.model.pcode.PcodeOp
  ): anvill.StackPointsTo.D = StackPointsTo(prog).update_op(pc, cont)
  // Members declared in anvill.PointsToContext

  def stackVnode(): Varnode =
    val reg = prog.getCompilerSpec().getStackPointer()
    Varnode(reg.getAddress, reg.getNumBytes)
  def getStackOffset(v: ARAValue): Option[Int] =
    v match {
      case RegDisp(vnode, off) =>
        for {
          int <- lift_to_op(off)
          singleton <- Some(int.lb)
          if int.cardinality == 1 && vnode.isRegister && stackVnode() == vnode
        } yield singleton.toInt // TODO(Ian) range check
      case _ => None
    }
    // TODO(Ian): with a strides we can do better here by selecting a variable access for each stride within the bound rather than relying on a singleton
  def pointsTo(
      cont: anvill.StackPointsTo.D,
      vnode: ghidra.program.model.pcode.Varnode,
      sz: anvill.ByteSize
  ): List[anvill.TypeVariableAccess] =
    (for {
      r <- vnodeToBasRegVnodeOrUnique(vnode)
      mp <- lift_to_op(cont)
      ara <- lift_to_op(mp(r))
      soffset <- getStackOffset(ara)
    } yield TypeVariableAccess(AbstractStack, ByteSize(soffset))).toList

}
