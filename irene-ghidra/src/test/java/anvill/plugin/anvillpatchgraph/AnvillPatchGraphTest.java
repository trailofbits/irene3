package anvill.plugin.anvillpatchgraph;

import static org.junit.Assert.*;

import anvill.plugin.anvillpatchgraph.graph.BasicBlockGraph;
import anvill.plugin.anvillpatchgraph.graph.BasicBlockVertex;
import ghidra.program.model.address.Address;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Objects;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class AnvillPatchGraphTest extends AbstractAnvillPatchGraphTest {

  private final ClassLoader classLoader = getClass().getClassLoader();
  private File patchGraphFile;

  public AnvillPatchGraphTest() {
    super();
  }

  @Override
  @After
  public void tearDown() {
    super.tearDown();
  }

  private void writeGraphProtobuf() throws IOException {
    getPatchGraph().writeTo(Files.newOutputStream(patchGraphFile.toPath()));
  }

  @Override
  @Before
  public void setUp() throws Exception {
    patchGraphFile =
        new File(
            Objects.requireNonNull(classLoader.getResource("patch-files/fake_sscanf_patchgraph.pb"))
                .getFile());
    // Uncomment this to regenerate the protobuf file.
    // NOTE: This will be written to the build directory and not the source directory, so you will
    // need to manually copy it
    // writeGraphProtobuf();
    super.setUp();
  }

  @Test
  public void testGraphSmoketest() {
    runSwing(() -> graphProvider.importPatchesFileSynchronous(patchGraphFile));
    BasicBlockGraph graph = getBasicBlockGraph();
    assertNotNull(graph);
    assertEquals(7, graph.getVertexCount());
  }

  @Test
  public void testGraphEdit() {
    runSwing(() -> graphProvider.importPatchesFileSynchronous(patchGraphFile));
    BasicBlockGraph graph = getBasicBlockGraph();

    Address address = getAddress("0x1004178");
    BasicBlockVertex vertex = graph.getVertexAtAddr(address);
    String text = "\n\t\tTest edit 1";
    String vertexText = runSwing(() -> vertex.getText());
    typeInGraph(vertex.getComponent(), text);
    assertDoNotContainsString(text, vertexText);
    runSwing(() -> vertex.setEditable(true));
    text =
        "\n\t\tthe quick brown fox jumped over the lazy dog THE QUICK BROWN FOX JUMPED OVER THE LAZY DOG 2";
    typeInGraph(vertex.getTextArea(), text);
    vertexText = runSwing(() -> vertex.getText());
    assertContainsString(text, vertexText);
  }

  @Test
  public void testBadPatch() {
    runSwing(
        () ->
            graphProvider.importPatchesFileSynchronous(
                new File(
                    Objects.requireNonNull(classLoader.getResource("patch-files/bad_sscanf.json"))
                        .getFile())));
    BasicBlockGraph graph = getBasicBlockGraph();
    assertNull(graph);
  }

  // NOTE: Remember to comment this so that tests don't take forever
  //  @Test
  public void testGraphInteractive() {
    runSwing(() -> graphProvider.importPatchesFileSynchronous(patchGraphFile));
    try {
      Thread.sleep(5 * 60 * 1000);
    } catch (InterruptedException e) {
    }
  }
}
