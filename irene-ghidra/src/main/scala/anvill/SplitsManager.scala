package anvill

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import upickle.default._
import scala.jdk.CollectionConverters.IteratorHasAsScala
import scala.jdk.CollectionConverters.SetHasAsJava

object SplitsManager:
  val SPLITS_MAP: String = "IRENE_SPLITS"
  val ZERO_BYTE_BLOCKS: String = "IRENE_ZERO_BLOCKS"
end SplitsManager

class AddressToAddressSet(val program: Program, val prop_name: String):
  private val prop_man = program.getUsrPropertyManager

  def inTransaction[T](f: => T): T =
    val txid = program.startTransaction("splits")
    val r = f
    program.endTransaction(txid, true)
    r

  private val map = Option(prop_man.getStringPropertyMap(prop_name)).getOrElse({
    inTransaction(prop_man.createStringPropertyMap(prop_name))
  })

  def getSet(addr: Address): Set[Address] =
    Option(map.getString(addr))
      .map(s => read[Set[(Int, Long)]](s))
      .getOrElse(Set())
      .map((id, off) =>
        program.getAddressFactory.getAddressSpace(id).getAddress(off)
      )

  def addToSet(addr: Address, split: Address) =
    inTransaction({
      val curr_splits = getSet(addr)
      val converted: Set[(Int, Long)] = (curr_splits + split).map(addr =>
        (addr.getAddressSpace.getSpaceID, addr.getOffset)
      )
      map.add(addr, write(converted))
    })

  def removeFromSet(addr: Address, split: Address) =
    inTransaction({
      val curr_splits = getSet(addr)
      val converted: Set[(Int, Long)] = (curr_splits - split).map(addr =>
        (addr.getAddressSpace.getSpaceID, addr.getOffset)
      )
      map.add(addr, write(converted))
    })

  def flatSet(): java.util.Set[(Address, Address)] =
    map.getPropertyIterator
      .iterator()
      .asScala
      .flatMap(a => getSet(a).map((a, _)))
      .toSet
      .asJava

end AddressToAddressSet

class SplitsManager(val program: Program) {
  private val splits_set =
    AddressToAddressSet(program, SplitsManager.SPLITS_MAP)
  private val zero_byte_blocks =
    AddressToAddressSet(program, SplitsManager.ZERO_BYTE_BLOCKS)

  def getSplitsForAddress(addr: Address): Set[Address] =
    splits_set.getSet(addr)

  def getSplitsForAddressJava(addr: Address): java.util.Set[Address] =
    getSplitsForAddress(addr).asJava

  def addSplitForAddress(addr: Address, split: Address) =
    splits_set.addToSet(addr, split)

  def removeSplitForAddress(addr: Address, split: Address) =
    splits_set.removeFromSet(addr, split)

  def getSplits(): java.util.Set[(Address, Address)] =
    splits_set.flatSet()

  def insertZeroByteBlock(addr: Address, zerostart: Address) =
    addSplitForAddress(addr, zerostart)
    zero_byte_blocks.addToSet(addr, zerostart)

  def getZeroBlocksForAddress(addr: Address): Set[Address] =
    zero_byte_blocks.getSet(addr)

  def getZeroBlocksForAddressJava(addr: Address): java.util.Set[Address] =
    getZeroBlocksForAddress(addr).asJava

  def removeZeroBlockForAddress(addr: Address, zerostart: Address) =
    zero_byte_blocks.removeFromSet(addr, zerostart)
}
