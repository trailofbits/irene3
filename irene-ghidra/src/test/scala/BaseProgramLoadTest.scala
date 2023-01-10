import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.test.TestEnv
import ghidra.base.project.GhidraProject
import ghidra.program.model.listing.Program
import java.io.File
import ghidra.util.task.TimeoutTaskMonitor
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import java.util.concurrent.TimeUnit
import ghidra.util.Msg

import org.junit.Before
import org.junit.Test
import org.junit.After

class BaseProgramLoadTest extends AbstractGhidraHeadlessIntegrationTest {
  var env: TestEnv = _
  var proj: GhidraProject = _
  def loadProgram(proj: GhidraProject, resourcePath: String): Program = {
    val file = File(
      getClass.getResource(resourcePath).getFile()
    )

    val prog = proj.importProgram(file)

    proj.analyze(prog, true)

    val monitor = TimeoutTaskMonitor.timeoutIn(10, TimeUnit.SECONDS)
    val analysisMgr = AutoAnalysisManager.getAnalysisManager(prog)
    analysisMgr.scheduleOneTimeAnalysis(
      analysisMgr.getAnalyzer("Decompiler Parameter ID"),
      prog.getMemory()
    )
    analysisMgr.startAnalysis(monitor)
    analysisMgr.waitForAnalysis(null, monitor)

    prog
  }

  @Before def buildenv(): Unit = {
    val logger = StderrLogger()

    Msg.setErrorLogger(logger)
    env = new TestEnv()

    proj = this.env.getGhidraProject()
  }

  @After def destroyenv(): Unit = {
    env.dispose()
  }

}
