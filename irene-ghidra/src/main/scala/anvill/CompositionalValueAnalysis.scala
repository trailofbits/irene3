package anvill

enum Space:
  case Uniq, Reg, Ram

case class ALoc(val spc: Space, val offset: Int, val byte_sz: Int)

sealed abstract class BaseVal

object Empty extends BaseVal
case class Parameter(val ind: Int) extends BaseVal
case class Register(val name: String) extends BaseVal

sealed abstract class DomainValue
case class DomainValue(
    val base: BaseVal,
    val offset: SignAgnosticStridedInterval
)

object DomainValue extends JoinSemiLatice[DomainValue] {

  override def tryCompare(x: DomainValue, y: DomainValue): Option[Int] = ???

  override def lteq(x: DomainValue, y: DomainValue): Boolean = ???

  override def join(lhs: DomainValue, rhs: DomainValue): DomainValue = ???

  override val bot: DomainValue = ???

}

object Dom extends MappingDomain[ALoc, DomainValue](DomainValue)

class MappingDomain[K, V](po: JoinSemiLatice[V])
    extends JoinSemiLatice[Map[K, V]] {

  override def join(
      lhs: Map[K, V],
      rhs: Map[K, V]
  ): Map[K, V] =
    lhs
      .foldLeft(rhs)((agg, k_v) =>
        agg.updated(k_v(0), po.join(k_v(1), rhs(k_v(0))))
      )
      .withDefaultValue(po.bot)

  override def lteq(x: Map[K, V], y: Map[K, V]): Boolean =
    (x.keys ++ y.keys).forall(k => po.lteq(x(k), y(k)))

  override def tryCompare(x: Map[K, V], y: Map[K, V]): Option[Int] =
    (x.keys ++ y.keys).foldLeft(Option(0))((curr, k) => {
      val xv = x(k)
      val yv = y(k)
      (curr, po.tryCompare(xv, yv)) match {
        case (None, _)                    => None
        case (_, None)                    => None
        case (Some(0), Some(0))           => Some(0)
        case (Some(x), Some(y)) if x == y => Some(x)
        case (Some(_), Some(_))           => None
      }
    })

  override val bot: Map[K, V] = Map().withDefaultValue(po.bot)
}

/** A compositional value analysis based on "Efficient Fine-Grained Binary
  * Instrumentation with Applications to Taint-Tracking"
  *
  * The basic idea is to express values in a domain of input registers, stack
  * values + an offset interval
  *
  * The domain of analysis is a mapping domain from a-loc -> symm + ESI
  */
class CompositionalValueAnalysis {}
