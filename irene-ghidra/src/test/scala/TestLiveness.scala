import org.junit.Test
import ghidra.program.model.listing.Program
import scala.jdk.CollectionConverters.IteratorHasAsScala
import anvill.BasicBlockContextProducer

import org.junit.Assert.assertEquals

class TestLiveness extends BaseProgramLoadTest {

  def firstFunctionNamed(
      prog: Program,
      nm: String
  ): ghidra.program.model.listing.Function = {
    prog
      .getFunctionManager()
      .getFunctions(true)
      .asScala
      .find(f => f.getName().equals(nm))
      .get
  }
  @Test def testLivenessCollatz(): Unit = {
    val coll_prog = loadProgram(proj, "binaries/collatz-x86")
    val func = firstFunctionNamed(coll_prog, "_leaf_function")
    val bb_cont = BasicBlockContextProducer(func)
    val live_info =
      bb_cont.liveness(coll_prog.getAddressFactory().getAddress("100003f94"))

    assertEquals(
      Set("RBX", "RSP", "RBP", "R12", "R13", "R14", "R15"),
      live_info.live_after
        .filter(p => p.reprVar.get.values(0).innerValue.isReg)
        .map(p => p.reprVar.get.values(0).innerValue.reg.get)
        .map(r => r.registerName)
        .toSet
    )
  }
}
