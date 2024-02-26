package anvill

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import upickle.default.*

import scala.jdk.CollectionConverters.IteratorHasAsScala
import scala.jdk.CollectionConverters.SetHasAsJava

object SplitsManager:
  val SPLITS_MAP: String = "IRENE_SPLITS"
  val ZERO_BYTE_BLOCKS: String = "IRENE_ZERO_BLOCKS"
end SplitsManager

class AddressToAddressSet(val program: Program, val prop_name: String):
  private val deleg = AddressToSet[(Int, Long)](program, "splits", prop_name)
  def tup_to_addr(id_off: (Int, Long)): Address =
    program.getAddressFactory.getAddressSpace(id_off._1).getAddress(id_off._2)
  def addr_to_tup(addr: Address): (Int, Long) =
    (addr.getAddressSpace.getSpaceID, addr.getOffset)

  def getSet(addr: Address): Set[Address] =
    deleg.getSet(addr).map(tup_to_addr)
  def addToSet(addr: Address, split: Address) =
    deleg.addToSet(addr, addr_to_tup(split))

  def removeFromSet(addr: Address, split: Address) =
    deleg.removeFromSet(addr, addr_to_tup(split))

  def flatSet(): java.util.Set[(Address, Address)] =
    deleg
      .flatSet()
      .map((addr, set_value) => (addr, tup_to_addr(set_value)))
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
