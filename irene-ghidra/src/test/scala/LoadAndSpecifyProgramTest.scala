import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.test.TestEnv
import scala.io.Source
import java.io.File
import skeleton.ProgramSpecifier

import org.junit.Before
import org.junit.Test
import ghidra.test.AbstractProgramBasedTest
import ghidra.util.Msg
import ghidra.util.ErrorLogger
import ghidra.framework.ToolUtils
import generic.test.AbstractGenericTest
import org.junit.Assert.assertNotNull

class StderrLogger extends ErrorLogger {

  override def debug(
      orig: Object,
      message: Object,
      exception: Throwable
  ): Unit = System.err.println(orig.toString() + ":" + message)

  override def debug(orig: Object, message: Object): Unit = {
    System.err.println(orig.toString() + ":" + message)
  }

  override def info(orig: Object, message: Object, x$2: Throwable): Unit =
    System.err.println(orig.toString() + ":" + message)

  override def info(orig: Object, message: Object): Unit =
    System.err.println(orig.toString() + ":" + message)

  override def trace(orig: Object, message: Object, x$2: Throwable): Unit =
    System.err.println(orig.toString() + ":" + message)

  override def trace(orig: Object, message: Object): Unit =
    System.err.println(orig.toString() + ":" + message)

  override def warn(orig: Object, message: Object, x$2: Throwable): Unit =
    System.err.println(orig.toString() + ":" + message)

  override def warn(orig: Object, message: Object): Unit =
    System.err.println(orig.toString() + ":" + message)

  override def error(orig: Object, message: Object, x$2: Throwable): Unit =
    System.err.println(orig.toString() + ":" + message)

  override def error(orig: Object, message: Object): Unit =
    System.err.println(orig.toString() + ":" + message)

}

class LoadAndSpecifyProgramTest extends AbstractGhidraHeadlessIntegrationTest { // extends AbstractProgramBasedTest {
  var env: TestEnv = _

  @Before def buildenv(): Unit = {
    val logger = StderrLogger()

    Msg.setErrorLogger(logger)
    env = new TestEnv()
  }

  @Test def specifyingHelloWorldShouldNotFail(): Unit = {
    val bin_file = new File(
      getClass.getResource("binaries/collatz-x86").getFile()
    )

    val prog = this.env.getGhidraProject().importProgram(bin_file)
    assertNotNull(prog)
    ProgramSpecifier.specifyProgram(prog)
  }
}
