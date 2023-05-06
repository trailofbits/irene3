import org.junit.Test
import ghidra.program.model.listing.Program
import scala.jdk.CollectionConverters.IteratorHasAsScala
import anvill.BasicBlockContextProducer
import anvill.LivenessAnalysis
import anvill.Util
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertFalse
import specification.specification.Parameter
import ghidra.program.model.lang.Register
import scala.collection.mutable
import anvill.Util.getLiveRegisters
import anvill.ProgramSpecifier
import ghidra.app.cmd.function.CallDepthChangeInfo
import ghidra.util.task.TaskMonitor

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
    val cdi = CallDepthChangeInfo(func, TaskMonitor.DUMMY)
    val cfg = ProgramSpecifier.getCFG(func)

    val bb_cont =
      BasicBlockContextProducer(
        func,
        cdi,
        ProgramSpecifier.maxDepth(func, cdi),
        cfg
      )
    val target_addr = coll_prog.getAddressFactory.getAddress("100003f94")
    val live_info =
      bb_cont.liveness(cfg.get(target_addr.getOffset).get)

    assertEquals(
      Set("R14", "RBX", "R13", "RSP", "R12", "R15", "RBP"),
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
    val cdi = CallDepthChangeInfo(func, TaskMonitor.DUMMY)
    val liveanalysis = anvill.LivenessAnalysis(
      anvill.Util.getCfgAsGraph(func),
      func,
      cdi,
      mutable.Map(),
      ProgramSpecifier.getCFG(func)
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
    val cdi = CallDepthChangeInfo(func, TaskMonitor.DUMMY)
    val cfg = ProgramSpecifier.getCFG(func)

    val bb_cont =
      BasicBlockContextProducer(
        func,
        cdi,
        ProgramSpecifier.maxDepth(func, cdi),
        cfg
      )
    val target_addr = prog.getAddressFactory.getAddress("401af0")
    val liveness_entry_block =
      bb_cont.liveness(cfg.get(target_addr.getOffset).get)

    assertTrue(
      "The value of  RDX should be dead",
      !getLiveRegisters(liveness_entry_block.live_after)
        .map(r => r.registerName)
        .contains("RDX")
    )

    val other_target_addr = prog.getAddressFactory.getAddress("00401b16")
    val live_info =
      bb_cont.liveness(cfg.get(other_target_addr.getOffset).get)

    val lives = getLiveRegisters(live_info.live_before).map(r => r.registerName)
    assertEquals(Set("EBX", "R14", "R13", "R12", "R15", "RSP"), lives)

    val lives_after =
      getLiveRegisters(live_info.live_after).map(r => r.registerName)
    assertEquals(
      Set("EBX", "RSI", "R14", "R13", "R12", "R15", "RSP", "RDX"),
      lives_after
    )
  }

  @Test def testSetDutyAffineEqs(): Unit = {
    val prog =
      loadProgram(proj, "binaries/challenge-3_amd64_program_c.elf")
    val func = firstFunctionNamed(prog, "set_duty")
    val cdi = CallDepthChangeInfo(func, TaskMonitor.DUMMY)
    val bb_prod =
      BasicBlockContextProducer(
        func,
        cdi,
        ProgramSpecifier.maxDepth(func, cdi),
        ProgramSpecifier.getCFG(func)
      )

    val stack_vals = bb_prod.getBlockContext(
      func.getEntryPoint(),
      prog.getAddressFactory().getAddress("00401b14")
    )

    val rsp_mapping = stack_vals.symvalsAtEntry.toSeq
      .find(vm => {
        val vals = vm.targetValue.get.values
        vals.length == 1 && vals(0).innerValue.isReg && vals(
          0
        ).innerValue.reg.get.registerName.equals("RSP")
      })
      .get

    assertTrue(rsp_mapping.currVal.get.inner.isStackDisp)
    assertEquals(0, rsp_mapping.currVal.get.inner.stackDisp.get)
  }

  @Test def mainStackVars(): Unit = {
    val prog =
      loadProgram(proj, "binaries/challenge-3_amd64_program_c.elf")
    val func = firstFunctionNamed(prog, "main")
    val cdi = CallDepthChangeInfo(func, TaskMonitor.DUMMY)

    val bb_prod =
      BasicBlockContextProducer(
        func,
        cdi,
        ProgramSpecifier.maxDepth(func, cdi),
        ProgramSpecifier.getCFG(func)
      )

    val orig_stack_locs = bb_prod.live_analysis.local_paramspecs().toSeq
    println(orig_stack_locs.flatMap(_.name).toSet)
    val legit_stack_locations = bb_prod.filterStackLocationsByStackDepth(
      bb_prod.max_depth,
      orig_stack_locs
    )
    val stack_var_names = legit_stack_locations.flatMap(_.name).toSet
    println(stack_var_names)
    assertFalse(stack_var_names.contains("cf"))
    assertTrue(stack_var_names.contains("local_b0"))
    assertTrue(stack_var_names.contains("local_128"))
  }

  @Test def testChal3SetPower(): Unit = {
    println("working on 00401920")
    val coll_prog =
      loadProgram(proj, "binaries/challenge-3_amd64_program_c.elf", true)
    val func = firstFunctionNamed(coll_prog, "set_power")
    val cdi = CallDepthChangeInfo(func, TaskMonitor.DUMMY)
    val cfg = ProgramSpecifier.getCFG(func)
    val bb_cont = BasicBlockContextProducer(
      func,
      cdi,
      ProgramSpecifier.maxDepth(func, cdi),
      cfg
    )
    val target_addr = coll_prog.getAddressFactory.getAddress("00401920")
    val live_info =
      bb_cont.liveness(cfg.get(target_addr.getOffset).get)
    println(cfg.get(target_addr.getOffset).get.outgoingBlocks)
    println(
      live_info.live_before.toSeq
        .groupBy(p => p.name.get)
        .map((nm, l) => (nm, l.length))
        .toMap
    )

    println(live_info.live_before)

    live_info.live_before.toSeq
      .filter(p => p.name.get == "p")
      .foreach(println);

    assertEquals(
      live_info.live_before.toSeq.map(p => p.name.get).toSet.toSeq.length,
      live_info.live_before.toSeq.length
    )

    assertEquals(
      Set("R14", "R13", "RSP", "ESI", "R15", "EDX", "RDI", "R12", "EBX"),
      live_info.live_after
        .filter(p => p.reprVar.get.values(0).innerValue.isReg)
        .map(p => p.reprVar.get.values(0).innerValue.reg.get)
        .map(r => r.registerName)
        .toSet
    )
  }

}
