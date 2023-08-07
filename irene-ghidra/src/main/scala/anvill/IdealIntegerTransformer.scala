package anvill

import ghidra.program.model.pcode.{PcodeOp, Varnode}

import math.Ordering.Implicits.infixOrderingOps
import scala.annotation.targetName

abstract class Interval[A] {
  val lb: A
  val ub: A
}

case class IntRange(lb: BigInt, ub: BigInt) extends Interval[BigInt] {
  val cardinality: BigInt = ((ub - lb) + 1).max(0)

  def hull(o: IntRange): IntRange = IntRange(lb.min(o.lb), ub.max(o.ub))

  def intersection(o: IntRange): IntRange = IntRange(lb.max(o.lb), ub.min(o.ub))

  @targetName("add")
  def +(o: IntRange): IntRange = IntRange(o.lb + lb, ub + o.ub)

  @targetName("sub")
  def -(o: IntRange): IntRange = IntRange(lb - o.ub, ub - o.lb)

  def eqitv(o: IntRange): IntRange =
    if o.cardinality == 1 && cardinality == 1 && o.lb == this.lb then
      IntRange(1, 1)
    else if o.intersection(this).cardinality <= 0 then IntRange(0, 0)
    else IntRange(BigInt(0), BigInt(1))

  @targetName("lognot")
  def unary_~ : IntRange =
    IntRange(~ub, ~lb)

  @targetName("neg")
  def unary_- : IntRange =
    IntRange(-ub, -lb)

  @targetName("mul")
  def *(o: IntRange): IntRange =
    val points =
      for
        ov <- List(o.lb, o.ub)
        tv <- List(this.lb, this.ub)
      yield ov * tv
    IntRange(points.min, points.max)

  override def toString: String = s"[$lb,$ub]"
}

trait CompleteLattice[D] extends JoinSemiLattice[D] {
  val top: D
}

trait IdealIntegerDomain[D] {
  // in theory we  could just call with opc INT_ADD but that gets really annoying
  def add_const(shift_val: BigInt, curr: D): D
  def op(opc: Int, values: List[D]): D
  def get_interval(bytesize: Int, context: D): IntRange
}

/*
Transforms an ideal integer domain with an ext+int


The goal here is to insulate clients from thinking about which operations preserve equality mod N

This is inspired by the approach in *Formally verified static anlaysis of C: Verasco* but we dont support
relational domains. Really this is designed for transforming a reduced product of congruences + intervals to get
ESIs without doing extra work.

 */

object IdealIntegerTransformer {

  def unsigned_range(bytesize: Int): IntRange = IntRange(0, card(bytesize))

  def card(bytesize: Int): BigInt = BigInt(2).pow(bytesize * 8)

  def signed_range(bytesize: Int): IntRange =
    IntRange(-card(bytesize) / 2, card(bytesize) / 2 + 1)

  // We want to shift a value D into
  def reduce_to_range[D](bytesize: Int, rng: IntRange, d: D)(using
      lat: CompleteLattice[D],
      ideal: IdealIntegerDomain[D]
  ): D = {
    val canidate_itv = ideal.get_interval(bytesize, d)
    val set_card = card(bytesize)
    if (canidate_itv.cardinality > card(bytesize)) {
      return lat.top
    }

    val shift_value = set_card * ((canidate_itv.lb - rng.lb) / set_card)
    if (canidate_itv.ub + shift_value) <= rng.ub then
      ideal.add_const(shift_value, d)
    else lat.top
  }

  given machine_transform[D](using
      ideal: IdealIntegerDomain[D],
      lat: CompleteLattice[D]
  ): MachineEval[D] with
    override def machine_eval(
        opc: Int,
        inputs: List[AnnotatedDomainObject[D]]
    ): D =
      opc match {
        // ops that preserve equality

        case PcodeOp.INT_NEGATE | PcodeOp.INT_2COMP | PcodeOp.INT_ADD |
            PcodeOp.INT_SUB | PcodeOp.COPY | PcodeOp.INT_AND | PcodeOp.INT_XOR |
            PcodeOp.INT_OR | PcodeOp.INT_MULT =>
          ideal.op(opc, inputs.map(_.d)) // TODO(Ian) is MUL right?

        // ops that require an unsigned range (equal does not need a specific range but we need to reduce it to a
        // range, whichever is suitable
        case PcodeOp.INT_EQUAL | PcodeOp.INT_NOTEQUAL | PcodeOp.INT_LESS |
            PcodeOp.INT_LESSEQUAL | PcodeOp.INT_ZEXT | PcodeOp.INT_CARRY |
            PcodeOp.INT_RIGHT | PcodeOp.INT_LEFT | PcodeOp.INT_DIV |
            PcodeOp.INT_REM =>
          ideal.op(
            opc,
            inputs.map(d =>
              reduce_to_range(d.bytesize, unsigned_range(d.bytesize), d.d)
            )
          )
        // ops that require a signed range
        case PcodeOp.INT_SLESS | PcodeOp.INT_SLESSEQUAL | PcodeOp.INT_SEXT |
            PcodeOp.INT_SCARRY | PcodeOp.INT_SBORROW | PcodeOp.INT_SDIV |
            PcodeOp.INT_SREM =>
          ideal.op(
            opc,
            inputs.map(d =>
              reduce_to_range(d.bytesize, signed_range(d.bytesize), d.d)
            )
          )
        case PcodeOp.INT_SRIGHT =>
          val lhs = inputs.head
          val rhs = inputs(1)
          ideal.op(
            opc,
            List(
              reduce_to_range(lhs.bytesize, signed_range(lhs.bytesize), lhs.d),
              reduce_to_range(rhs.bytesize, unsigned_range(rhs.bytesize), rhs.d)
            )
          )
        case _ => lat.top
      }

}
