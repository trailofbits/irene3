package anvill

/*
Given an a JoinSemiLattice for V creates a JoinSemiLattice for a Map[K,V].
MappingDomain wraps a map to guarantee that all operations are performed on a default map
that produces bottom when required.
 */

class MappingDomain[K, V](private val mp: Map[K, V]) {
  def updated(k: K, v: V) = new MappingDomain(mp.updated(k, v))

  def apply(k: K): V = mp(k)

  def keysIterator: Iterator[K] = mp.keysIterator

  override def toString: String = s"MappingDomain(${mp.toString()})"

  override def equals(obj: Any): Boolean =
    obj match {
      case m: MappingDomain[_, _] => mp.equals(m.mp)
      case _                      => false
    }

  override def hashCode(): Int = mp.hashCode()
}

object MappingDomain {

  def apply[K, V](mp: Map[K, V])(using
      j: JoinSemiLattice[V]
  ): MappingDomain[K, V] = new MappingDomain(mp.withDefault(_ => j.bot))

  given [K, V](using
      wd: Widen[V],
      j: JoinSemiLattice[V]
  ): WidenCompletedDom[MappingDomain[K, V]] with
    override def step(
        prev: MappingDomain[K, V],
        curr: MappingDomain[K, V],
        curr_step: Long
    ): CompleteLifting[MappingDomain[K, V]] =
      Elem(
        MappingDomain(
          (prev.mp.keysIterator ++ curr.mp.keysIterator)
            .map(k => (k, wd.step(prev.mp(k), curr.mp(k), curr_step)))
            .toMap
        )
      )

  given [K, V](using
      lat: JoinSemiLattice[V]
  ): JoinSemiLattice[MappingDomain[K, V]] with
    val bot: MappingDomain[K, V] = MappingDomain(
      Map.empty.withDefault(_ => lat.bot)
    )

    def join(
        lhs: MappingDomain[K, V],
        rhs: MappingDomain[K, V]
    ): MappingDomain[K, V] =
      MappingDomain(
        (lhs.mp.keysIterator ++ rhs.mp.keysIterator)
          .map(k => (k, lat.join(lhs.mp(k), rhs.mp(k))))
          .toMap
      )

    // Members declared in scala.math.PartialOrdering
    def lteq(x: MappingDomain[K, V], y: MappingDomain[K, V]): Boolean =
      (x.mp.keysIterator ++ y.mp.keysIterator).forall(k =>
        lat.lteq(x.mp(k), y.mp(k))
      )

    def tryCompare(
        x: MappingDomain[K, V],
        y: MappingDomain[K, V]
    ): Option[Int] =
      val compared = (x.mp.keysIterator ++ y.mp.keysIterator)
        .map(k => lat.tryCompare(x.mp(k), y.mp(k)))
        .toList
      compared.headOption.flatten.flatMap(hyp =>
        Option.when(compared.forall(v => v.contains(hyp)))(hyp)
      )
}
