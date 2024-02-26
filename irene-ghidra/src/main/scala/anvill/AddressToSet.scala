package anvill

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import upickle.default.{Reader, read, write, Writer}

import scala.jdk.CollectionConverters.IteratorHasAsScala
import scala.jdk.CollectionConverters.SetHasAsJava

class AddressToSet[V](
    val program: Program,
    val tname: String,
    val prop_name: String
)(using Reader[V], Writer[V]):
  private val prop_man = program.getUsrPropertyManager

  def inTransaction[T](f: => T): T =
    val txid = program.startTransaction(tname)
    val r = f
    program.endTransaction(txid, true)
    r

  private val map = Option(prop_man.getStringPropertyMap(prop_name)).getOrElse({
    inTransaction(prop_man.createStringPropertyMap(prop_name))
  })

  def getSet(addr: Address): Set[V] =
    Option(map.getString(addr))
      .map(s => read[Set[V]](s))
      .getOrElse(Set())

  def addToSet(addr: Address, split: V) =
    inTransaction({
      val curr_splits = getSet(addr)
      val converted: Set[V] = curr_splits + split
      map.add(addr, write(converted))
    })

  def removeFromSet(addr: Address, split: V) =
    inTransaction({
      val curr_splits = getSet(addr)
      val converted: Set[V] = curr_splits - split
      map.add(addr, write(converted))
    })

  def flatSet(): Set[(Address, V)] =
    map.getPropertyIterator
      .iterator()
      .asScala
      .flatMap(a => getSet(a).map((a, _)))
      .toSet

end AddressToSet
