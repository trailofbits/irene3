import anvill.ProgramSpecifier
import anvill.macho.{ArcRuntime, ObjcSpecifier}
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.base.project.GhidraProject
import ghidra.program.model.listing.Program
import ghidra.test.{AbstractGhidraHeadedIntegrationTest, TestEnv}
import ghidra.util.Msg
import ghidra.util.task.TimeoutTaskMonitor
import org.junit.Assert.{assertEquals, assertFalse, assertTrue}
import org.junit.{After, Before, Test}

import java.io.File
import java.util.concurrent.TimeUnit

/** Phase 7.1 — ObjC protocol + category enumeration. Uses a
 *  dedicated `arm64-macos-objc-categories.dylib` fixture that
 *  declares a `Greeter` protocol, a class conforming to it, and a
 *  category that extends the class. Existing fixtures (and their
 *  phase0–phase6 goldens) are untouched.
 */
class ObjcProtocolCategoryTest extends AbstractGhidraHeadedIntegrationTest {
  private var env: TestEnv = _

  private val categoriesFile: File =
    File(getClass.getResource("binaries/arm64-macos-objc-categories.dylib").getFile)
  private val collatzFile: File =
    File(getClass.getResource("binaries/arm64-macos-collatz").getFile)

  private var categoriesProg: Program = _
  private var collatzProg: Program = _

  private def loadProgram(proj: GhidraProject, file: File): Program = {
    val prog = proj.importProgram(file)
    proj.analyze(prog, true)
    val monitor = TimeoutTaskMonitor.timeoutIn(60, TimeUnit.SECONDS)
    val mgr = AutoAnalysisManager.getAnalysisManager(prog)
    mgr.startAnalysis(monitor)
    mgr.waitForAnalysis(null, monitor)
    prog
  }

  @Before def buildEnv(): Unit = {
    Msg.setErrorLogger(new StderrLogger)
    env = new TestEnv()
    val proj = env.getGhidraProject
    categoriesProg = loadProgram(proj, categoriesFile)
    collatzProg = loadProgram(proj, collatzFile)
  }

  @After def tearDown(): Unit = env.dispose()

  // ------------------------------------------------------------------
  //  Pure parser unit tests
  // ------------------------------------------------------------------

  @Test def parsesCategoryLabelInstance(): Unit = {
    assertEquals(
      Some(("-", "Hello", "Loud", "shout:")),
      ObjcSpecifier.parseCategoryLabel("-[Hello(Loud)_shout:]")
    )
  }

  @Test def parsesCategoryLabelWithSpace(): Unit = {
    assertEquals(
      Some(("-", "Hello", "Loud", "shout:")),
      ObjcSpecifier.parseCategoryLabel("-[Hello(Loud) shout:]")
    )
  }

  @Test def parsesCategoryLabelClassSide(): Unit = {
    assertEquals(
      Some(("+", "NSString", "Helpers", "emptyString")),
      ObjcSpecifier.parseCategoryLabel("+[NSString(Helpers)_emptyString]")
    )
  }

  @Test def rejectsNonCategoryLabel(): Unit = {
    assertEquals(None, ObjcSpecifier.parseCategoryLabel("-[Hello greet:]"))
    assertEquals(None, ObjcSpecifier.parseCategoryLabel("plain_function"))
    assertEquals(None, ObjcSpecifier.parseCategoryLabel("-[Hello("))
    assertEquals(None, ObjcSpecifier.parseCategoryLabel("-[Hello()_sel]"))
  }

  // ------------------------------------------------------------------
  //  Integration tests on the categories dylib
  // ------------------------------------------------------------------

  /** The `Greeter` user-defined protocol must surface as a protocol
   *  sentinel. Inherited `NSObject` protocols may or may not also
   *  appear depending on Ghidra's analyser — the invariant is "at
   *  least `Greeter`".
   */
  @Test def greeterProtocolEmitted(): Unit = {
    val spec = ProgramSpecifier.specifyProgram(categoriesProg)
    val protocols = spec.symbols.filter(_.name.startsWith(ArcRuntime.objcProtocolSentinel))
    assertFalse(
      "Expected at least one __irene_objc_protocol_ sentinel",
      protocols.isEmpty
    )
    assertTrue(
      s"Expected the Greeter protocol sentinel; saw: " +
        protocols.map(_.name).mkString(", "),
      protocols.exists(_.name == s"${ArcRuntime.objcProtocolSentinel}Greeter")
    )
  }

  /** The `Hello(Loud)` category must surface at least once — the
   *  `shout:` selector is the uniquely-categorized method.
   */
  @Test def loudCategoryEmitted(): Unit = {
    val spec = ProgramSpecifier.specifyProgram(categoriesProg)
    val cats = spec.symbols.filter(_.name.startsWith(ArcRuntime.objcCategorySentinel))
    assertFalse(
      "Expected at least one __irene_objc_category_ sentinel",
      cats.isEmpty
    )
    assertTrue(
      s"Expected a sentinel mentioning Hello(Loud) shout:; saw: " +
        cats.map(_.name).mkString(", "),
      cats.exists(s => s.name.contains("Hello(Loud)") && s.name.contains("shout:"))
    )
  }

  /** Scoping guard: plain C binaries must not gain any protocol or
   *  category sentinels.
   */
  @Test def plainArm64HasNoProtocolOrCategorySentinels(): Unit = {
    val spec = ProgramSpecifier.specifyProgram(collatzProg)
    val sentinels = spec.symbols.filter { s =>
      s.name.startsWith(ArcRuntime.objcProtocolSentinel) ||
        s.name.startsWith(ArcRuntime.objcCategorySentinel)
    }
    assertTrue(
      s"Plain C binary must not emit protocol/category sentinels; saw: " +
        sentinels.map(_.name).mkString(", "),
      sentinels.isEmpty
    )
  }
}
