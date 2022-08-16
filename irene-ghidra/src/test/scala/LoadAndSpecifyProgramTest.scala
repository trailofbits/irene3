import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.test.TestEnv
import scala.io.Source
import java.io.File
import skeleton.ProgramSpecifier

import org.junit.Before
import org.junit.Test

class LoadAndSpecifyProgramTest extends AbstractGhidraHeadlessIntegrationTest {

  var env: TestEnv = _

  @Before def initialize(): Unit = {
    println(this.getClass.getName)
    env = new TestEnv(this.getClass.getName)
  }

  @Test def specifyingHelloWorldShouldNotFail(): Unit = {
    val bin_file = new File(
      getClass.getResource("binaries/collatz-x86").getFile()
    )
    val prog = this.env.getGhidraProject().importProgram(bin_file)

    ProgramSpecifier.specifyProgram(prog)
  }
}
