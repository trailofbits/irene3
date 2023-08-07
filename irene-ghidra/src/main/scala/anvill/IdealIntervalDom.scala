package anvill
import cats.Applicative
import cats.syntax.all.*
import ghidra.program.model.pcode.PcodeOp
import cats.Monad

import scala.annotation.tailrec

/*
Implements a standard interval domain over unbounded integers. The soundness of this domain relies on
the ideal integer transformer which lazily transforms values into strict signed and unsigned ranges for operations
that do not preserve equality across modular arithmetic. In the future it may be beneficial to have a bits domain as well
 */

object IdealIntervalDom {
  type IntervalDomValue = CompleteLifting[IntRange]

  given widening: WidenCompletedDom[IntRange] with
    override def step(
        prev: IntRange,
        curr: IntRange,
        step: Long
    ): CompleteLifting[IntRange] = {
      // TODO(Ian): we are widening both edges when 1 would be sufficient
      if step >= 5 && lat.tryCompare(prev, curr).forall(_ < 0) then Top()
      else Elem(curr)
    }

  type BinopTransformer =
    (IntervalDomValue, IntervalDomValue) => IntervalDomValue

  def lift2(
      f: (IntRange, IntRange) => IntRange
  ): (CompleteLifting[IntRange], CompleteLifting[IntRange]) => CompleteLifting[
    IntRange
  ] =
    (x, y) => (x, y).mapN(f)

  def simulate2(
      f: (BigInt, BigInt) => BigInt
  )(x: IntervalDomValue, y: IntervalDomValue): IntervalDomValue =
    (x, y).flatMapN((xe, ye) => {
      if (xe.cardinality == 1 && ye.cardinality == 1) {
        val nval: BigInt = f(xe.lb, ye.lb)
        Elem(IntRange(nval, nval))
      } else { Top() }
    })

  def lift(
      f: (IntRange) => IntRange
  ): CompleteLifting[IntRange] => CompleteLifting[
    IntRange
  ] = app_lifting.lift(f)

  private val add = lift2(_ + _)
  private val sub = lift2(_ - _)
  private val inteq = lift2(_ eqitv _)
  private val or = simulate2(_ | _)
  private val and = simulate2(_ & _)
  private val xor = simulate2((x, y) => (x | y) & (~(x & y)))
  private val shl = simulate2(_ << _.toInt) // TODO(Ian) Check if in range
  private val shr = simulate2(_ >> _.toInt)
  private val mul = lift2(_ * _)
  private val intneg = lift(~_)
  private val int2comp = lift(-_)
  private val bool_negate = lift(IntRange(1, 1) - _)
  private val intnoteq = (x: IntervalDomValue, y: IntervalDomValue) =>
    bool_negate(inteq(x, y))

  given lat: JoinSemiLattice[IntRange] with
    override val bot: IntRange = IntRange(0, -1)
    override def join(lhs: IntRange, rhs: IntRange): IntRange = lhs.hull(rhs)

    def lteq(x: anvill.IntRange, y: anvill.IntRange): Boolean =
      x.cardinality <= 0 || x.ub <= y.ub && x.lb >= y.lb
    def tryCompare(x: anvill.IntRange, y: anvill.IntRange): Option[Int] =
      if x == y || (x.cardinality == 0 && y.cardinality == 0) then Some(0)
      else if lteq(x, y) then Some(-1)
      else if lteq(y, x) then Some(1)
      else None

  given IdealIntegerDomain[CompleteLifting[IntRange]] with
    override def add_const(
        shift_val: BigInt,
        curr: CompleteLifting[IntRange]
    ): CompleteLifting[IntRange] =
      add(app_lifting.pure(IntRange(shift_val, shift_val)), curr)

    def is_bot(x: CompleteLifting[IntRange]): Boolean =
      x match {
        case Top()    => false
        case Elem(el) => el.cardinality == 0
      }

    val bot_val: CompleteLifting[IntRange] = Elem(IntRange(0, -1))

    override def op(
        opc: Int,
        values: List[CompleteLifting[IntRange]]
    ): CompleteLifting[IntRange] =
      def binop(t: BinopTransformer): CompleteLifting[IntRange] =
        if is_bot(values.head) || is_bot(values(1)) then bot_val
        else t(values.head, values(1))

      def unop(
          t: CompleteLifting[IntRange] => CompleteLifting[IntRange]
      ): CompleteLifting[IntRange] =
        if is_bot(values.head) then bot_val else t(values.head)

      opc match {
        case PcodeOp.COPY         => values.head
        case PcodeOp.INT_ADD      => binop(add)
        case PcodeOp.INT_SUB      => binop(sub)
        case PcodeOp.INT_OR       => binop(or)
        case PcodeOp.INT_AND      => binop(and)
        case PcodeOp.INT_XOR      => binop(xor)
        case PcodeOp.INT_EQUAL    => binop(inteq)
        case PcodeOp.INT_NEGATE   => unop(intneg)
        case PcodeOp.INT_2COMP    => unop(int2comp)
        case PcodeOp.INT_MULT     => binop(mul)
        case PcodeOp.INT_NOTEQUAL => binop(intnoteq)
        case PcodeOp.INT_LEFT     => binop(shl)
        case PcodeOp.INT_RIGHT | PcodeOp.INT_SRIGHT =>
          binop(shr) // sign range restriction should handle the sright case
        case PcodeOp.INT_ZEXT =>
          values.head // this is a little sketchy but since it's restriced to the unsigned range
        // zext just behaves as id
        case _ => Top()
      }

    override def get_interval(
        bytesize: Int,
        context: CompleteLifting[IntRange]
    ): IntRange = context match {
      case Top()   => IntRange(0, BigInt(2).pow(bytesize * 8))
      case Elem(e) => e
    }

}
