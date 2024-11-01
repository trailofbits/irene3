package anvill;

import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeFalse;

import anvill.decompiler.DecompilerServerException;
import anvill.decompiler.DockerDecompilerServerManager;
import anvill.plugin.PatchLowerInput;
import compiler.DockerCommandLineDriver;
import compiler.PatchCompiler;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TimeoutTaskMonitor;
import io.grpc.Grpc;
import io.grpc.InsecureChannelCredentials;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import specification.specification.Specification;

public class ServerManagerTest extends AbstractGhidraHeadlessIntegrationTest {
  private Program program;
  protected TestEnv env;

  private boolean inGitHubActions() {
    return System.getenv("CI") != null;
  }

  @Before
  public void setUp() throws Exception {
    if (inGitHubActions()) {
      return;
    }

    env = new TestEnv(this.getClass().getName());
    var proj = this.env.getGhidraProject();

    var rec = getClass().getResource("binaries/arm-linux-gnueabihf-fibonacci");
    // var rec = getClass().getResource("binaries/collatz-x86");
    Objects.requireNonNull(rec);
    var f = new File(rec.getFile());
    program = proj.importProgram(f);

    proj.analyze(program, true);

    var monitor = TimeoutTaskMonitor.timeoutIn(10, TimeUnit.SECONDS);
    var analysisMgr = AutoAnalysisManager.getAnalysisManager(program);
    // analysisMgr.scheduleOneTimeAnalysis(
    //         analysisMgr.getAnalyzer("Decompiler Parameter ID"),
    //         program.getMemory()
    // );
    analysisMgr.startAnalysis(monitor);
    analysisMgr.waitForAnalysis(null, monitor);
  }

  @After
  public void tearDown() {
    if (inGitHubActions()) {
      return;
    }

    if (program != null && env != null) {
      env.release(program);
    }
    program = null;
    if (env != null) {
      env.dispose();
    }
    env = null;
  }

  @Test
  public void startPatchlangServer() throws DecompilerServerException {
    assumeFalse(inGitHubActions());

    var man = new DockerDecompilerServerManager(50080);
    man.startPatchLangServer();

    var grpcChannel =
        Grpc.newChannelBuilder("localhost:50080", InsecureChannelCredentials.create()).build();
    PatchLangGrpcClient grpc_cl = new PatchLangGrpcClient(grpcChannel);
    try {
      Thread.sleep(5000);
    } catch (InterruptedException interruptedException) {
      // Don't care
    }
    var func =
        program
            .getFunctionManager()
            .getFunctionContaining(program.getAddressFactory().getAddress("00010698"));
    var sym_set = new scala.collection.immutable.HashSet<Symbol>();
    var spec = ProgramSpecifier.specifySingleFunction(func, sym_set);
    var res = grpc_cl.processSpec(Specification.toJavaProto(spec));
    assertTrue(res.isPresent());
  }

  @Test
  public void testCompileExample() throws IOException {
    assumeFalse(inGitHubActions());

    var man = new PatchCompiler(new DockerCommandLineDriver());
    var moduletxt =
        Files.readString(new File(getClass().getResource("ex_patch_mod.irene").getFile()).toPath());
    var demo = getClass().getResource("binaries/libroscpp.so");
    Objects.requireNonNull(demo);
    var input =
        new PatchLowerInput("", "cortex-a8", "", new File(demo.getFile()), "", false, false);
    man.compileModule(moduletxt, 87, input);
  }
}
