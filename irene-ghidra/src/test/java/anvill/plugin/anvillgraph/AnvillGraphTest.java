package anvill.plugin.anvillgraph;

import static org.junit.Assert.*;

import anvill.plugin.anvillgraph.graph.BasicBlockGraph;
import java.io.File;
import java.util.Objects;
import org.junit.Before;
import org.junit.Test;

public class AnvillGraphTest extends AbstractAnvillGraphTest {

  private final ClassLoader classLoader = getClass().getClassLoader();

  public AnvillGraphTest() {
    super();
  }

  @Override
  @Before
  public void setUp() throws Exception {
    super.setUp();
  }

  @Test
  public void testGraphSmoketest() {
    runSwing(
        () ->
            graphProvider.importPatchesFile(
                new File(
                    Objects.requireNonNull(classLoader.getResource("patch-files/fake_sscanf.json"))
                        .getFile())));
    BasicBlockGraph graph = getBasicBlockGraph();
    assertNotNull(graph);
    assertEquals(7, graph.getVertexCount());
  }

  @Test
  public void testBadPatch() {
    runSwing(
        () ->
            graphProvider.importPatchesFile(
                new File(
                    Objects.requireNonNull(classLoader.getResource("patch-files/bad_sscanf.json"))
                        .getFile())));
    BasicBlockGraph graph = getBasicBlockGraph();
    assertNull(graph);
  }

  // NOTE: Remember to comment this so that tests don't take forever
  //  @Test
  public void testGraphInteractive() {
    runSwing(
        () ->
            graphProvider.importPatchesFile(
                new File(
                    Objects.requireNonNull(classLoader.getResource("patch-files/fake_sscanf.json"))
                        .getFile())));
    try {
      Thread.sleep(5 * 60 * 1000);
    } catch (InterruptedException e) {
    }
  }
}
