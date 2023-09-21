import ghidra.program.model.lang.Register
import ghidra.program.model.listing.{
  Instruction,
  Program,
  Function as GFunction
}
import ghidra.program.model.pcode.{PcodeOp, Varnode}
import org.junit.{Before, Test}
import anvill.ARAValue.given
import anvill.CompleteLifting.given
import anvill.ComputeNodeContext.CFG
import anvill.IdealIntervalDom.given
import anvill.{
  BaseVariable,
  CfgEdge,
  CfgNode,
  ComparablePcodeOp,
  CompleteLifting,
  ComputeNodeContext,
  ConstructedType,
  DerivedTypeVariable,
  EntDefiner,
  EntryRegValue,
  EqCons,
  MappingDomain,
  Op,
  OpDefiner,
  PcodeLabel,
  ReachingDefinitions,
  ReachingDefsNodeSol,
  SolvingErrors,
  SubTypeConstraint,
  TypeAnalysis,
  TypeConstraint,
  TypeSolvingContext,
  TypeVariable
}
import ghidra.program.model.address.{AddressRange, AddressRangeImpl, AddressSet}
import scalax.collection.edges.DiEdgeImplicits
import ReachingDefinitions.given

import scala.jdk.CollectionConverters.*
import org.junit.Assert.{assertEquals, assertTrue}
import scalax.collection.OuterEdge
import scalax.collection.io.dot.*

class ChallengeTest extends BaseGzfTest {
  var create_conn_prog: Program = _
  var create_conn_func: GFunction = _
  var sp_reg: Register = _
  var sp_vnode: Varnode = _

  def varnodeForReg(regname: String): Varnode =
    val reg: Register = create_conn_prog.getLanguage.getRegister(regname)
    Varnode(reg.getAddress, reg.getNumBytes)

  @Before
  def setupCreateConn(): Unit = {
    this.create_conn_prog = loadGzf(proj, "ghidra_dbs/chal10-ppc-vle.gzf")
    this.create_conn_func = create_conn_prog.getFunctionManager
      .getFunctions(true)
      .iterator()
      .asScala
      .find(_.getName().equals("create_conn"))
      .get

    this.sp_reg = create_conn_prog.getCompilerSpec.getStackPointer
    this.sp_vnode = Varnode(sp_reg.getAddress, sp_reg.getNumBytes)
  }

  @Test
  def testConstraintsForDB(): Unit = {
    val typ_a = TypeAnalysis(
      create_conn_func
    )

    val rng = AddressSet()
    val cons = typ_a.analyzeWithAddressSetView(rng, true)
    cons.foreach(println(_))
    assertTrue(
      "One of the constraints should have an entryreg representing the parameter, otherwise we missed the mark",
      cons
        .collect({ case SubTypeConstraint(lhs, rhs) => List(lhs, rhs) })
        .flatten
        .exists((x: DerivedTypeVariable) => x.base.isInstanceOf[EntryRegValue])
    )
  }

  @Test def testReachingDefsForStore(): Unit = {
    val pc = instructionAt("0082cf22").getPcode()(2)
    val typ_a = TypeAnalysis(
      create_conn_func
    )

    val rdef = typ_a.analyzeReachingDefs()
    val r3 = varnodeForReg("r3")
    assertEquals(Set(EntDefiner(r3)), rdef(pc)(r3))
  }

  @Test def hasRegConstraint(): Unit = {
    val typ_a = TypeAnalysis(
      create_conn_func
    )

    val rng = AddressSet()
    rng.add(getInstructionAddressRange("0082cf22"))
    val r3 = varnodeForReg("r3")
    val cons = typ_a.analyzeWithAddressSetView(rng, false)

    val expected_cons = DerivedTypeVariable(EntryRegValue(r3), List())
    // expect r3 entry stored
    assertTrue(
      "_R3 is stored",
      cons
        .collect({ case SubTypeConstraint(lhs, rhs) => List(lhs, rhs) })
        .flatten
        .contains(expected_cons)
    )
  }

  def instructionAt(addrs: String): Instruction =
    val addr = create_conn_prog.getAddressFactory.getAddress(addrs)
    val insn = create_conn_prog.getListing.getInstructionAt(addr)
    insn

  def getInstructionAddressRange(addrs: String): AddressRange =
    val insn = instructionAt(addrs)
    AddressRangeImpl(insn.getMinAddress, insn.getMaxAddress)

  @Test def testTypeConsSolutionWithSubProcTypes(): Unit = {
    val typ_a = TypeAnalysis(
      create_conn_func
    )

    val rng = AddressSet()
    rng.add(getInstructionAddressRange("0082cf22"))
    rng.add(getInstructionAddressRange("0082cf76"))

    val r7_tv = Op(instructionAt("0082cf76").getPcode.last)

    val cons = typ_a.analyzeWithAddressSetView(rng, true)

    val ty_repr = TypeSolvingContext().solve(cons).get_sol(r7_tv)
    // get the type solution for the load it should be equal to our in parameter and consequently a pointer to a struct
    assertTrue(
      "should have a concrete type for the loaded r7",
      ty_repr.isDefined
    )

    assertEquals("Transport *", ty_repr.get.getDisplayName)
  }

  @Test def avoidOverUnification(): Unit = {
    val typ_a = TypeAnalysis(
      create_conn_func
    )

    val cons = typ_a.analyze()

    val r7_tv = Op(instructionAt("0082cf76").getPcode.last)

    val ty_repr = TypeSolvingContext().solve(cons).get_sol(r7_tv)
    // get the type solution for the load it should be equal to our in parameter and consequently a pointer to a struct
    assertTrue(
      "should have a concrete type for the loaded r7",
      ty_repr.isDefined
    )

    assertEquals("Transport *", ty_repr.get.getDisplayName)
  }

  import implicits._
  def renderCfg(cfg: CFG, order: Option[Map[CfgNode, Int]]): String = {
    val root = DotRootGraph(directed = true, id = Some("CFG"))
    def edgeTransformer(
        edge: CFG#InnerEdge
    ): Option[(DotGraph, DotEdgeStmt)] = {
      val eo = edge.outer
      val label = eo.label
      val get_order = (n: CfgNode) =>
        order.map(m => m(n).toString).getOrElse("None")
      Some(
        root,
        DotEdgeStmt(
          NodeId(eo.source.toString + " order: " + get_order(eo.source) + "."),
          NodeId(eo.target.toString + " order: " + get_order(eo.target) + "."),
          List(DotAttr(Id("label"), Id(label.toString)))
        )
      )
    }
    cfg.toDot(root, edgeTransformer)
  }

  @Test def rdefsForCallContainCallOnly(): Unit = {
    val pc = instructionAt("0082cf9c").getPcode()(1)
    val typ_a = TypeAnalysis(
      create_conn_func
    )

    val rdef = typ_a.analyzeReachingDefs()
    val sol = ReachingDefsNodeSol(create_conn_prog)

    val post = sol.execute(rdef(pc), pc)

    val r3 = varnodeForReg("_r3")
    println(r3)

    val tvs = sol.access(post, r3)
    assertEquals(Set(Op(pc)), tvs)
  }

  @Test def ensureCallNotUnified(): Unit = {
    val typ_a = TypeAnalysis(
      create_conn_func
    )

    val rng = AddressSet()
    rng.add(getInstructionAddressRange("0082cf22"))
    rng.add(getInstructionAddressRange("0082cf76"))
    rng.add(getInstructionAddressRange("0082cf9c"))

    val cons = typ_a.analyzeWithAddressSetView(rng, true)

    cons.foreach(println(_))
    val r7_tv = Op(instructionAt("0082cf76").getPcode.last)

    val ty_repr = TypeSolvingContext().solve(cons).get_unique_sol(r7_tv)
    // get the type solution for the load it should be equal to our in parameter and consequently a pointer to a struct
    assertTrue(
      "should have a concrete type for the loaded r7, that is unique",
      ty_repr.isDefined
    )

    assertEquals("Transport *", ty_repr.get.getDisplayName)
  }

  @Test def reachingDefsForCall(): Unit = {
    val typ_a = TypeAnalysis(
      create_conn_func
    )

    val rdef = ReachingDefsNodeSol(create_conn_prog)

    val nd_0 =
      typ_a.analyzeReachingDefs()(instructionAt("082cf80").getPcode()(0))
    assertTrue(
      "Should have def for r3",
      rdef.access(nd_0, varnodeForReg("r3")).nonEmpty
    )

    val nd = typ_a.analyzeReachingDefs()(instructionAt("082cf80").getPcode()(1))
    assertTrue(
      "Should have def for r3",
      rdef.access(nd, varnodeForReg("r3")).nonEmpty
    )
  }

  @Test def ensureAddrSeparateFromLoad(): Unit = {
    val typ_a = TypeAnalysis(
      create_conn_func
    )

    val rng = AddressSet()
    rng.add(getInstructionAddressRange("0082cf76"))
    rng.add(getInstructionAddressRange("0082cf78"))
    rng.add(getInstructionAddressRange("0082cf7c"))
    rng.add(getInstructionAddressRange("0082cf7e"))
    rng.add(getInstructionAddressRange("0082cf80"))

    val cons = typ_a.analyzeWithAddressSetView(rng, false)

    cons.foreach(println(_))

    val ty_repr = TypeSolvingContext().solve(cons)

    ty_repr.get_sol(baseVariableForSeqnum("0082cf76", 3).tv)
  }

  def rootCauseFailure(
      cons: List[TypeConstraint],
      watch: (ConstructedType, ConstructedType)
  ): Option[EqCons] = {
    try
      TypeSolvingContext().debug_solve_watch_constraints(cons, Some(watch))
      None
    catch
      case e: SolvingErrors.WatchedUnificationException =>
        val eq_cons = e.reason
        println("watch:" + watch)
        println(eq_cons)
        if eq_cons == EqCons(watch._1, watch._2) || eq_cons == EqCons(
            watch._2,
            watch._1
          )
        then Some(eq_cons)
        else rootCauseFailure(cons, (eq_cons.lhs, eq_cons.rhs))
  }

  def baseVariableForSeqnum(addr: String, ind: Int): BaseVariable =
    BaseVariable(Op(instructionAt(addr).getPcode()(ind)))

  @Test def ensureUniqueSolution(): Unit = {
    val typ_a = TypeAnalysis(
      create_conn_func
    )

    val cons = typ_a.analyze()

    val r7_tv = Op(instructionAt("0082cf76").getPcode.last)

    // println("Root cause: " + rootCauseFailure(cons, (BaseVariable(r7_tv), BaseVariable(Op(instructionAt("0082cf9c").getPcode()(1))))))

    println(
      "Root cause: " + rootCauseFailure(
        cons,
        (
          baseVariableForSeqnum("0082cf76", 0),
          baseVariableForSeqnum("0x82cf76", 3)
        )
      )
    )

    val ty_repr = TypeSolvingContext().solve(cons).get_unique_sol(r7_tv)
    // get the type solution for the load it should be equal to our in parameter and consequently a pointer to a struct
    assertTrue(
      "should have a concrete type for the loaded r7, that is unique",
      ty_repr.isDefined
    )

    assertEquals("Transport *", ty_repr.get.getDisplayName)
  }
}
