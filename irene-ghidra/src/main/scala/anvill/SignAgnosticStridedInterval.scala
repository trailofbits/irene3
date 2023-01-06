package anvill

import scala.collection.immutable.Range.BigInt.apply
import scala.math.Ordered.orderingToOrdered
import scala.math.BigDecimal.RoundingMode

final class BitVectorWidthMismatch(val w1: Int, val w2: Int)
    extends Exception("Mismatch between " + w1 + " and " + w2)

class BitVector(val v: BigInt, val w: Int) {

  def gcd: BitVector => BitVector =
    BitVector.checked_binop((x, y) => x.gcd(y), this, _)

  def - : BitVector => BitVector =
    BitVector.wrapped_checked_binop((x, y) => x - y, this, _)
}

object BitVector {
  given Ordering[BitVector] with
    def compare(bvx: BitVector, bvy: BitVector) =
      bvx.v.compare(bvy.v)

  def wrap_value(x: BitVector): BitVector = {
    BitVector(x.v.mod(2 ^ x.w), x.w)
  }

  @throws(classOf[BitVectorWidthMismatch])
  def wrapped_checked_binop(
      op: (BigInt, BigInt) => BigInt,
      x: BitVector,
      y: BitVector
  ) = {
    wrap_value(checked_binop(op, x, y))
  }

  def relative_lte(x: BitVector)(a: BitVector, b: BitVector) = {
    (a - x) <= (b - x)
  }

  @throws(classOf[BitVectorWidthMismatch])
  def checked_binop(
      op: (BigInt, BigInt) => BigInt,
      x: BitVector,
      y: BitVector
  ) = {
    if x.w != y.w then throw BitVectorWidthMismatch(x.w, y.w)
    else BitVector(op(x.v, y.v), x.w)
  }
}

sealed abstract class SignAgnosticStridedInterval {
  def member(x: BitVector): Boolean = {
    this match {
      case SASIBot    => false
      case SASITop(_) => true
      case SASIValue(sr, lb, ub) =>
        BitVector.relative_lte(lb)(x, ub) && (ub - x).v.mod(sr) == 0
    }
  }

  def cardinality(): BigInt = {
    this match {
      case SASIBot    => BigInt(0)
      case SASITop(w) => BigInt(2) ^ w
      case SASIValue(sr, lb, ub) =>
        (BigDecimal((ub - lb).v + 1) / BigDecimal(sr))
          .setScale(0, RoundingMode.FLOOR)
          .toBigInt
    }
  }

}

/** This domain is described in: "BinTrimmer: Towards Static Binary Debloating
  * Through Abstract Interpretation"
  *
  * Unfortunatley the widening operation is presented in: "Signedness-Agnostic
  * Program Analysis: Precise Integer Bounds for Low-Level Code"
  *
  * NOTE(Ian): this domain defines a pseudo-join operator meaning that there are
  * infinite ascending chains, if these chains aren't flattened by a widening
  * operator when this domain is used we may not terminate
  */
case class SASIValue(
    val sr: BigInt,
    val lb: BitVector,
    val ub: BitVector
) extends SignAgnosticStridedInterval {
  if lb.w != ub.w then throw BitVectorWidthMismatch(lb.w, ub.w)
}

case class SASITop(val w: Int) extends SignAgnosticStridedInterval
object SASIBot extends SignAgnosticStridedInterval

object SignAgnosticStridedInterval
    extends JoinSemiLattice[SignAgnosticStridedInterval] {

  override def tryCompare(
      x: SignAgnosticStridedInterval,
      y: SignAgnosticStridedInterval
  ): Option[Int] = {
    if lteq(x, y) && lteq(y, x) then Some(0)
    else if lteq(x, y) then Some(-1)
    else if lteq(y, x) then Some(1)
    else None
  }

  override def lteq(
      x: SignAgnosticStridedInterval,
      y: SignAgnosticStridedInterval
  ): Boolean = (x, y) match {
    case (_, SASITop(_)) => true
    case (SASITop(_), _) => false
    case (SASIBot, _)    => true
    case (_, SASIBot)    => false
    case (SASIValue(sx, lx, ux), SASIValue(sy, ly, uy)) => {
      (lx == ly && ux == uy && (sy % sx) == 0) || (y.member(lx) && y.member(
        ux
      ) && !x.member(ly) && !x.member(uy) && (ly - lx).v.mod(sy) == 0 && sx.mod(
        sy
      ) == 0)
    }
  }

  // NOTE(Ian): this is a semi-join because if we view the domain as a number circle, on a join we can either cover both
  // SASIs by extending the one on the "right", around to cover values on the left, or extend the "value" around to the right.
  // These two covering SASIs will be incomparable, so instead we bias the join.
  override def join(
      lhs: SignAgnosticStridedInterval,
      rhs: SignAgnosticStridedInterval
  ): SignAgnosticStridedInterval = {
    if lteq(lhs, rhs) then lhs
    else if lteq(rhs, lhs) then rhs
    else {
      val SASIValue(s_lhs, lb_lhs, ub_lhs) = lhs
      val SASIValue(s_rhs, lb_rhs, ub_rhs) = rhs

      val shared_stried = s_lhs.gcd(s_rhs)
      // we join together by wrapping from the lb on the left up to the upper bound on the rhs
      val left_bias =
        SASIValue(shared_stried.gcd((ub_rhs - lb_lhs).v), lb_lhs, ub_rhs)
      val right_bias =
        SASIValue(shared_stried.gcd((ub_lhs - lb_rhs).v), lb_rhs, ub_lhs)
      // incomparible but contain eachother's bound means neither stride is compatible

      val is_upper_bound = (x: SignAgnosticStridedInterval) =>
        (lteq(lhs, x) && lteq(rhs, x))
      (is_upper_bound(left_bias), is_upper_bound(right_bias)) match {
        case (false, false) => SASITop(lb_rhs.w)
        case (true, false)  => left_bias
        case (false, true)  => right_bias
        case (true, true) => {
          // both valid so need to check cardinality
          if left_bias.cardinality() < right_bias.cardinality() then left_bias
          else right_bias
        }

      }

    }
  }

  override val bot: SignAgnosticStridedInterval = SASIBot

  def abstraction_function(
      bvs: Set[BitVector]
  ): SignAgnosticStridedInterval = {
    if (bvs.isEmpty) then bot
    else {
      val svals = bvs.toSeq.sorted
      val lowest = svals.head
      val sr = svals
        .zip(svals.tail)
        .map((small, large) => large - small)
        .reduce((x, y) => x.gcd(y))
      val ub = svals.last
      SASIValue(sr.v, lowest, ub)
    }
  }
}
