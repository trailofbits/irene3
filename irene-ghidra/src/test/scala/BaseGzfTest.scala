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

class BaseGzfTest extends AbstractGhidraHeadlessIntegrationTest {
  var env: TestEnv = _
  var proj: GhidraProject = _
  def loadGzf(
      proj: GhidraProject,
      resourcePath: String
  ): Program = {
    val file = File(
      getClass.getResource(resourcePath).getFile()
    )

    val prog = proj.importProgram(file)

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
