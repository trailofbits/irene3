import org.junit.Test
import anvill.{
  ARAValue,
  CfgEdge,
  ComparablePcodeOp,
  ComputeNodeContext,
  Const,
  Elem,
  GuardLabel,
  IntRange,
  MappingDomain,
  PcodeForwardFixpoint,
  PcodeLabel,
  RegDisp,
  StackPointsTo,
  TypeAnalysis
}
import ghidra.program.model.address.{AddressRange, AddressSet}
import ghidra.program.model.block.BasicBlockModel

import scala.jdk.CollectionConverters.*
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertFalse
import org.junit.Before
import ghidra.program.model.listing.{Program, Function as GFunction}
import ghidra.program.model.pcode.{PcodeOp, Varnode}
import ghidra.util.task.TaskMonitor
import ghidra.program.model.address.AddressRangeImpl
import anvill.ARAValue.given
import anvill.CompleteLifting.given
import anvill.IdealIntervalDom.given
import ghidra.program.model.lang.Register

class TestTypeConstraints extends BaseGzfTest {
  var create_conn_prog: Program = _
  var create_conn_func: GFunction = _
  var sp_reg: Register = _
  var sp_vnode: Varnode = _

  @Before
  def setupCreateConn(): Unit = {
    this.create_conn_prog =
      loadGzf(proj, "ghidra_dbs/create_conn_ppc_slice.gzf")
    this.create_conn_func = create_conn_prog.getFunctionManager
      .getFunctions(true)
      .iterator()
      .asScala
      .find(_.getName().equals("create_conn"))
      .get

    this.sp_reg = create_conn_prog.getCompilerSpec.getStackPointer
    this.sp_vnode = Varnode(sp_reg.getAddress, sp_reg.getNumBytes)
  }

  /*
        000000b4 7a 01 00 16     e_ble      LAB_000000ca
                                                      $U4eb80:1 = COPY 0:1
                                                      $U800:4 = INT_SUB 3:4, 1:4
                                                      $U900:1 = INT_RIGHT cr0, $U800:4
                                                      $U4eb80:1 = INT_AND $U900:1, 1:1
                                                      $U4eb80:1 = BOOL_NEGATE $U4eb80:1
                                                      $U4fe80:1 = INT_EQUAL $U4eb80:1, 0:1
                                                      CBRANCH *[ram]0xb8:4, $U4fe80:1
                                                      BRANCH *[ram]0xca:4
        000000b8 70 e0 e0 83     e_lis      r7,0x83
                                                      $U5c680:8 = INT_ZEXT 0x83:2
                                                      r7 = INT_LEFT $U5c680:8, 16:4
   */
  @Test def testCbranchEitherFallsThroughToBranchOrHitsZext(): Unit = {
    val ble = create_conn_prog.getListing.getInstructionAt(
      create_conn_prog.getAddressFactory.getAddress("000000b4")
    )
    val elis = create_conn_prog.getListing.getInstructionAt(
      create_conn_prog.getAddressFactory.getAddress("000000b8")
    )
    val elis_zext = elis.getPcode()(0)
    val cbr = ble.getPcode()(6)
    val fallthrough_br = ble.getPcode()(7)

    assertEquals(PcodeOp.CBRANCH, cbr.getOpcode)
    assertFalse(ComputeNodeContext.normalControlFlow(cbr))

    val cbr_edges = ComputeNodeContext
      .edges(create_conn_func)(ble)
      .filter(e => e.source == cbr)
    assertEquals(2, cbr_edges.length)
    assertEquals(
      Set(
        CfgEdge(cbr, GuardLabel(cbr.getInput(1), false), fallthrough_br),
        CfgEdge(cbr, GuardLabel(cbr.getInput(1), true), elis_zext)
      ),
      cbr_edges.toSet
    )
  }

  @Test def testCbranchShouldHaveTwoIntLefts(): Unit = {
    val intra_flow = create_conn_prog.getListing.getInstructionAt(
      create_conn_prog.getAddressFactory.getAddress("00000042")
    )
    val cbr = intra_flow.getPcode()(7)
    val fallthrough_int_left = intra_flow.getPcode()(8)
    val jump_int_left = intra_flow.getPcode()(15)

    assertEquals(PcodeOp.CBRANCH, cbr.getOpcode)
    assertFalse(ComputeNodeContext.normalControlFlow(cbr))

    val cbr_edges = ComputeNodeContext
      .edges(create_conn_func)(intra_flow)
      .filter(e => e.source == cbr)
    assertEquals(2, cbr_edges.length)
    assertEquals(
      Set(
        CfgEdge(cbr, GuardLabel(cbr.getInput(1), false), fallthrough_int_left),
        CfgEdge(cbr, GuardLabel(cbr.getInput(1), true), jump_int_left)
      ),
      cbr_edges.toSet
    )
  }

  /** 00000024 07 67 se_subf r7,r6 r7 = INT_SUB r6, r7 00000026 00 e7 se_extzh
    * r7 r7 = INT_ZEXT _r7:2
    */
  @Test def testGetEdgesFallthroughOp(): Unit = {
    val insn0 = create_conn_prog.getListing.getInstructionAt(
      create_conn_prog.getAddressFactory.getAddress("00000024")
    )
    val insn1 = create_conn_prog.getListing.getInstructionAt(
      create_conn_prog.getAddressFactory.getAddress("00000026")
    )
    val to_execute_op = insn0.getPcode()(0)
    assertTrue(ComputeNodeContext.normalControlFlow(to_execute_op))
    assertEquals(
      List(
        CfgEdge(to_execute_op, PcodeLabel(to_execute_op), insn1.getPcode()(0))
      ),
      ComputeNodeContext.edges(create_conn_func)(insn0)
    )
  }
  @Test def testCFGCreateConn(): Unit = {
    val cfg = ComputeNodeContext.func_to_cfg(create_conn_func)
    val def_ent = cfg.nodes
      .filter(_.incoming.isEmpty)
      .map(x => {
        x.outer
      })

    val insn0 = create_conn_prog.getListing.getInstructionAt(
      create_conn_prog.getAddressFactory.getAddress("00000024")
    )
    val insn1 = create_conn_prog.getListing.getInstructionAt(
      create_conn_prog.getAddressFactory.getAddress("00000026")
    )

    assertEquals(
      PcodeLabel(insn0.getPcode()(0)),
      cfg.edges
        .find(e =>
          e.source == insn0.getPcode()(0) && e.target == insn1.getPcode()(0)
        )
        .get
        .label
    )
    assertEquals(1, def_ent.size)
  }

  @Test def testTypeConstraintsCreateConn(): Unit = {
    val typ_a = TypeAnalysis(
      create_conn_func
    )

    typ_a.analyze()
  }

  def getInstructionAddressRange(addrs: String): AddressRange =
    val addr = create_conn_prog.getAddressFactory.getAddress(addrs)
    val insn = create_conn_prog.getListing.getInstructionAt(addr)
    AddressRangeImpl(insn.getMinAddress, insn.getMaxAddress)

  /*
  Test that we have enough constraints to do the entailment we actually want
  The ideal entailment here is Transport* <= create_conn.in_0 <= r7@00000062

  with unification this should hopefully look like ptr Transport = create_conn.in_0 = r7 ish

  so this is mostly a transitivity proof so the test looks for a path between in and r7 defined at 62
   */
  @Test def testTypeConstraintsEntry(): Unit = {
    val typ_a = TypeAnalysis(
      create_conn_func
    )

    val rng = AddressSet()
    /*                           LAB_00000062                                    XREF[1]:     00000032(j)
        00000062 c2 7f           se_lwz     r7,0x2(r31)
                                                      $U4fa00:8 = INT_LEFT 2:8, 2:4
                                                      $U4fb00:8 = INT_ADD r31, $U4fa00:8
                                                      $U52c80:4 = LOAD ram($U4fb00:8)
                                                      r7 = INT_ZEXT $U52c80:4*/

    rng.add(getInstructionAddressRange("000000062"))
    /*0000000e d2 3f           se_stw     tp,0x2(r31)
                                              $U4fa00:8 = INT_LEFT 2:8, 2:4
                                              $U4fb00:8 = INT_ADD r31, $U4fa00:8
                                              STORE ram($U4fb00:8), _r3*/

    rng.add(getInstructionAddressRange("0000000e"))

    // from the load and the store + the function entry constraints we should have enough to prove our entailment
    typ_a.analyzeWithAddressSetView(rng).foreach(println(_))
  }

  @Test def intLeftStackPts(): Unit = {
    val stw = create_conn_prog.getListing.getInstructionAt(
      create_conn_prog.getAddressFactory.getAddress("0000000e")
    )
    val shl = stw.getPcode()(0)
    val spt = StackPointsTo.apply(create_conn_prog)
    val new_ara = spt.evalExpr(shl, Elem(MappingDomain(Map.empty)))
    assertTrue(new_ara.isDefined)

    assertEquals(Const(Elem(IntRange(8, 8))), new_ara.get())
  }
  @Test def testPointsToRelationshipOnStore(): Unit = {
    val typ_a = TypeAnalysis(
      create_conn_func
    )

    val points_to_res = typ_a.analyzePointsTo()

    val stw = create_conn_prog.getListing.getInstructionAt(
      create_conn_prog.getAddressFactory.getAddress("0000000e")
    )
    val tgt_pcode_store = stw.getPcode()(2)
    val shl = stw.getPcode()(0)

    assertEquals(PcodeOp.STORE, tgt_pcode_store.getOpcode)
    assertEquals(PcodeOp.INT_LEFT, shl.getOpcode)

    val curr_dom = points_to_res(tgt_pcode_store)
    assertTrue(curr_dom.isDefined)

    val const_should_be_8 = curr_dom.get()(shl.getOutput)
    assertTrue(const_should_be_8.isDefined)

    assertEquals(Elem(Const(Elem(IntRange(8, 8)))), const_should_be_8)

    val ara_stw_address = curr_dom.get()(tgt_pcode_store.getInput(1)).get()

    // r31 gets r1 where r1 -32 + 8
    assertEquals(RegDisp(sp_vnode, Elem(IntRange(-24, -24))), ara_stw_address)
  }

  @Test def testPointsToRelationshipOnLoad(): Unit = {
    val typ_a = TypeAnalysis(
      create_conn_func
    )

    val points_to_res = typ_a.analyzePointsTo()

    val ldw = create_conn_prog.getListing.getInstructionAt(
      create_conn_prog.getAddressFactory.getAddress("000000062")
    )

    val ld_pcode = ldw.getPcode()(2)
    assertEquals(PcodeOp.LOAD, ld_pcode.getOpcode)
    val curr_dom = points_to_res(ld_pcode).get()(ld_pcode.getInput(1)).get()
    assertEquals(RegDisp(sp_vnode, Elem(IntRange(-24, -24))), curr_dom)
  }
}
