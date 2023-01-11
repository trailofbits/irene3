import org.junit.Test
import ghidra.program.model.listing.Program
import scala.jdk.CollectionConverters.IteratorHasAsScala
import anvill.BasicBlockContextProducer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import specification.specification.Parameter
import ghidra.program.model.lang.Register
import scala.collection.mutable
import anvill.Util.getLiveRegisters

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

  @Test def testCfgSetDuty(): Unit = {
    val prog = loadProgram(proj, "binaries/challenge-3_amd64_program_c.elf")
    val func = firstFunctionNamed(prog, "set_duty")
    val cfg = anvill.Util
      .getCfgAsGraph(func)
    val es = anvill.Util.getEdgeSet(cfg)
    es.foreach((f, s) => println(f.toHexString + " " + s.toHexString))
    assertEquals(
      Set(
        (0x401af0, 0x401b16),
        (0x401af0, 0x401b22),
        (0x401b16, 0x401b2c),
        (0x401b22, 0x401b2c)
      ),
      es
    )

    assertEquals(4, cfg.nodes.length)

  }

  @Test def testChal3SetDutyKillsFromBlock(): Unit = {
    val prog = loadProgram(proj, "binaries/challenge-3_amd64_program_c.elf")
    val func = firstFunctionNamed(prog, "set_duty")
    val liveanalysis = anvill.LivenessAnalysis(
      anvill.Util.getCfgAsGraph(func),
      func,
      mutable.Map()
    )

    val target_insn = prog
      .getListing()
      .getInstructionAt(prog.getAddressFactory().getAddress("00401b1b"))

    val copy_op = target_insn.getPcode()(0)

    assertEquals(
      Set("RDX", "EDX"),
      getLiveRegisters(liveanalysis.kill(copy_op, target_insn))
        .map(r => r.registerName)
    )
  }

  @Test def testChal3SetDuty(): Unit = {
    println("working on 00401920")

    val prog = loadProgram(proj, "binaries/challenge-3_amd64_program_c.elf")
    val func = firstFunctionNamed(prog, "set_duty")

    val bb_cont = BasicBlockContextProducer(func)

    val liveness_entry_block =
      bb_cont.liveness(prog.getAddressFactory().getAddress("401af0"))

    assertTrue(
      "The value of  RDX should be dead",
      !getLiveRegisters(liveness_entry_block.live_after)
        .map(r => r.registerName)
        .contains("RDX")
    )

    val live_info =
      bb_cont.liveness(prog.getAddressFactory().getAddress("00401b16"))

    val lives = getLiveRegisters(live_info.live_before).map(r => r.registerName)
    assertEquals(Set("EBX", "R14", "R13", "R12", "R15", "RSP"), lives)

    val lives_after =
      getLiveRegisters(live_info.live_after).map(r => r.registerName)
    assertEquals(
      Set("EBX", "RSI", "R14", "R13", "R12", "R15", "RSP", "RDX"),
      lives_after
    )
  }

  @Test def testChal3SetPower(): Unit = {
    println("working on 00401920")
    val coll_prog =
      loadProgram(proj, "binaries/challenge-3_amd64_program_c.elf")
    val func = firstFunctionNamed(coll_prog, "set_power")
    val bb_cont = BasicBlockContextProducer(func)
    val live_info =
      bb_cont.liveness(coll_prog.getAddressFactory().getAddress("00401920"))

    println(
      live_info.live_before.toSeq
        .groupBy(p => p.name.get)
        .map((nm, l) => (nm, l.length))
        .toMap
    )

    live_info.live_before.toSeq
      .filter(p => p.name.get == "p")
      .foreach(println);

    assertEquals(
      live_info.live_before.toSeq.map(p => p.name.get).toSet.toSeq.length,
      live_info.live_before.toSeq.length
    )

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
