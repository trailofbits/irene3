import anvill.ProgramSpecifier
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.base.project.GhidraProject
import ghidra.program.model.listing.Program
import ghidra.test.{AbstractGhidraHeadedIntegrationTest, TestEnv}
import ghidra.util.Msg
import ghidra.util.task.TimeoutTaskMonitor
import org.junit.{After, Before, Test}

import java.io.{File, FileOutputStream}
import java.util.concurrent.TimeUnit

/**
 * Regenerates the Phase 0 golden specs by running
 * `ProgramSpecifier.specifyProgram` on each Mach-O fixture and writing
 * the protobuf output to `src/test/resources/specs/<name>.phase0.spec.pb`.
 *
 * This test intentionally captures today's (possibly buggy) behaviour so
 * that later phases can diff against concrete change. It is a helper, not
 * an assertion suite — the assertion is "the test runs without throwing
 * and produces non-empty output files".
 *
 * The goldens are written into the source tree so they can be committed
 * alongside the fixtures. Re-run this test whenever the fixtures or the
 * specifier change and you want to re-baseline.
 */
class CapturePhase0GoldensTest extends AbstractGhidraHeadedIntegrationTest {

  private val fixtures: Seq[String] = Seq(
    "arm64-macos-collatz",
    "arm64-macos-objc-hello.dylib",
    "arm64-macos-swift-hello",
    "arm64e-macos-sample",
    "arm64-ios-encrypted-stub",
  )

  /** Resolves the source-tree specs directory relative to the working
   *  directory (gradle runs tests from the project root or the module
   *  root; handle both). Returns the classpath-resolved copy under
   *  `build/resources/test/specs/` as a fallback so the test never
   *  silently targets an unexpected location.
   */
  private val specsDir: File = {
    val candidates = Seq(
      File("irene-ghidra/src/test/resources/specs"),
      File("src/test/resources/specs"),
    )
    val sourceTree = candidates.find(_.getParentFile.exists)
    val dir = sourceTree.getOrElse {
      val binDir = File(getClass.getResource("binaries/collatz-x86").getFile).getParentFile
      File(binDir.getParentFile, "specs")
    }
    dir.mkdirs()
    dir
  }

  private var env: TestEnv = _
  private var proj: GhidraProject = _

  @Before def buildEnv(): Unit = {
    Msg.setErrorLogger(new StderrLogger)
    env = new TestEnv()
    proj = env.getGhidraProject
  }

  @After def tearDown(): Unit = env.dispose()

  private def loadProgram(file: File): Program = {
    val prog = proj.importProgram(file)
    proj.analyze(prog, true)
    val monitor = TimeoutTaskMonitor.timeoutIn(30, TimeUnit.SECONDS)
    val analysisMgr = AutoAnalysisManager.getAnalysisManager(prog)
    analysisMgr.startAnalysis(monitor)
    analysisMgr.waitForAnalysis(null, monitor)
    prog
  }

  @Test def regeneratePhase0Goldens(): Unit = {
    fixtures.foreach { name =>
      val resource = getClass.getResource(s"binaries/$name")
      if (resource == null) {
        System.err.println(s"[phase0-golden] skipping missing fixture: $name")
      } else {
        val src = File(resource.getFile)
        val prog = loadProgram(src)
        val txid = prog.startTransaction("capture-phase0-golden")
        val dst = File(specsDir, s"$name.phase0.spec.pb")
        try {
          val out = new FileOutputStream(dst)
          try ProgramSpecifier.specifyProgram(prog).writeTo(out)
          finally out.close()
        } finally {
          prog.endTransaction(txid, false)
        }
        System.err.println(s"[phase0-golden] wrote ${dst.getAbsolutePath} (${dst.length} bytes)")
      }
    }
  }
}
