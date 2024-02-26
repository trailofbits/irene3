package anvill

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program

import scala.jdk.CollectionConverters.SetHasAsJava

object RequiredSymbolsManager:
  val REQ_SYMS: String = "REQUIRED_SYMBOLS"
end RequiredSymbolsManager

class RequiredSymbolsManager(val prog: Program) {
  private val symb_set =
    AddressToSet[String](prog, "symbols", RequiredSymbolsManager.REQ_SYMS)

  def addSymbol(addr: Address, symb: String) =
    symb_set.addToSet(addr, symb)

  def removeSymbol(addr: Address, symb: String) =
    symb_set.removeFromSet(addr, symb)

  def getRequiredSymbols(addr: Address): java.util.Set[String] =
    symb_set.getSet(addr).asJava
}
