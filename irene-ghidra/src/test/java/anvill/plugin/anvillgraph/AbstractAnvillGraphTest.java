/* ###
 * Adapted from upstream Ghidra 10.1.5
 * Copied/Adapted from 'AbstractFunctionGraphTest'
 *
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package anvill.plugin.anvillgraph;

import static org.junit.Assert.assertNotNull;

import anvill.plugin.anvillgraph.graph.BasicBlockGraph;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.graph.viewer.options.RelayoutOption;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.ProgramLocation;
import ghidra.test.*;
import java.util.ArrayList;
import java.util.List;
import org.junit.Before;

public abstract class AbstractAnvillGraphTest extends AbstractGhidraHeadedIntegrationTest {

  protected PluginTool tool;
  protected AnvillGraphPlugin graphPlugin;
  protected ProgramDB program;
  protected TestEnv env;
  protected AnvillGraphProvider graphProvider;
  protected CodeBrowserPlugin codeBrowser;
  protected String startAddressString = "0100415a";// sscanf
  protected List<String> functionAddrs = new ArrayList<>();

  @Before
  public void setUp() throws Exception {

    setErrorGUIEnabled(false);

    env = getEnv();
    tool = env.getTool();

    initializeTool();
  }

  protected TestEnv getEnv() throws Exception {
    return new TestEnv(getClass().getName());
  }

  protected void initializeTool() throws Exception {
    installPlugins();

    openProgram();
    ProgramManager pm = tool.getService(ProgramManager.class);
    pm.openProgram(program.getDomainFile());

    showTool(tool);

    // NOTE: Must be before showing graph because we don't handle creation when moving
    goToAddress(getStartingAddress());

    showAnvillGraphProvider();

    setInstanceField("relayoutOption", graphPlugin.getGraphOptions(),
        RelayoutOption.VERTEX_GROUPING_CHANGES);
  }

  protected void openProgram() throws Exception {
    ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder("sample", true);
    // TODO: Toy sleigh files are not installed
//    ToyProgramBuilder builder = new ToyProgramBuilder("sample", true);
//    builder.createMemory("sscanf", "0x0100415a", 80);
//
//    functionAddrs.add("0x0100415a");
//
//    build_sscanf(builder);
//
    program = builder.getProgram();
  }

  private void build_sscanf(ToyProgramBuilder builder) throws MemoryAccessException {
		/*
		 Originally from notepad 'sscanf'

		 	A
		 	|->	B
		 	|
		 	C
		 	|-> D
		 	|	|-> E
		 	|
		 	F
		 	|
		 	G

		 */

    // A - 9 code units
    builder.addBytesNOP("0x0100415a", 1);
    builder.addBytesNOP("0x0100415b", 2);
    builder.addBytesNOP("0x0100415d", 3);
    builder.addBytesNOP("0x01004160", 2);
    builder.addBytesNOP("0x01004162", 7);
    builder.addBytesNOP("0x01004169", 3);
    builder.addBytesNOP("0x0100416c", 3);
    builder.addBytesNOP("0x0100416f", 7);
    builder.addBytesBranchConditional("0x01004176", "0x01004192");// jump to C

    // B - 10 code units (fallthrough from A)
    // 0x01004178
    builder.addBytesNOP("0x01004178", 3);
    builder.addBytesNOP("0x0100417b", 1);
    builder.addBytesNOP("0x0100417c", 3);
    builder.addBytesNOP("0x0100417f", 1);
    builder.addBytesNOP("0x01004180", 3);
    builder.addBytesNOP("0x01004183", 1);
    builder.addBytesNOP("0x01004184", 2);
    builder.addBytesNOP("0x01004186", 3);
    builder.addBytesNOP("0x01004189", 3);
    builder.addBytesNOP("0x0100418c", 6);// was a call

    // C - 2 code units
    // 0x01004192
    builder.addBytesNOP("0x01004192", 2);
    builder.addBytesBranchConditional("0x01004194", "0x0100419c");// jump to F

    // D - 2 code units (fallthrough from C)
    // 0x01004196
    builder.addBytesNOP("0x01004196", 4);
    builder.addBytesBranchConditional("0x0100419a", "0x010041a1");// jump to E

    // F - 2 code unit
    // 0x0100419c
    builder.addBytesNOP("0x0100419c", 3);
    builder.addBytesBranch("0x0100419f", "0x010041a4");// jump to G

    // E - 1 code units
    // 0x010041a1
    builder.addBytesNOP("0x010041a1", 3);

    // G - 2 code units
    // 0x010041a4
    builder.addBytesNOP("0x010041a4", 1);
    builder.addBytesReturn("0x010041a5");

    builder.disassemble("0x0100415a", 80, true);

    //
    //
    //
    builder.createLabel("0x0100415a", "sscanf");
    builder.createFunction("0x0100415a");
  }

  protected String getStartingAddress() {
    return startAddressString;
  }

  protected void showAnvillGraphProvider() {
    AnvillGraphProvider provider = (AnvillGraphProvider) tool.getComponentProvider(
        AnvillGraphPlugin.GRAPH_NAME);
    tool.showComponentProvider(provider, true);

    graphProvider = waitForComponentProvider(AnvillGraphProvider.class);
    assertNotNull("Graph not shown", graphProvider);

    installTestGraphLayout(provider);
  }

  protected void installTestGraphLayout(AnvillGraphProvider provider) {
    // TODO
  }

  protected void installPlugins() throws PluginException {
    tool.addPlugin(CodeBrowserPlugin.class.getName());
    tool.addPlugin(AnvillGraphPlugin.class.getName());

    graphPlugin = env.getPlugin(AnvillGraphPlugin.class);
    codeBrowser = env.getPlugin(CodeBrowserPlugin.class);
  }

  protected Address getAddress(String addressString) {
    AddressFactory factory = program.getAddressFactory();
    return factory.getAddress(addressString);
  }

  protected ProgramLocation getLocationForAddressString(String addressString) {
    Address address = getAddress(addressString);
    return new ProgramLocation(program, address);
  }

  protected void goToAddress(String addressString) {
    ProgramLocation location = getLocationForAddressString(addressString);
    codeBrowser.goTo(location, true);

    waitForSwing();
//    waitForBusyGraph();
  }

  protected BasicBlockGraph getBasicBlockGraph() {
    return graphProvider.getGraph();
  }
}
