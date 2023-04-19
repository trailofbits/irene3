/* ###
 * Adapted from upstream Ghidra 10.1.5
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
package anvill.plugin.anvillgraph.layout;

import anvill.plugin.anvillgraph.graph.BasicBlockGraph;
import ghidra.framework.options.Options;
import ghidra.util.task.TaskMonitor;
import javax.swing.Icon;
import resources.ResourceManager;

public class DecompilerNestedLayoutProvider extends AnvillGraphLayoutProviderExtensionPoint {

  private static final Icon ICON =
      ResourceManager.loadImage("images/function_graph_code_flow.png");
  static final String LAYOUT_NAME = "Nested Code Layout";

  @Override
  public BBGraphLayout getAnvillGraphLayout(BasicBlockGraph graph, TaskMonitor monitor) {
    DecompilerNestedLayout layout = new DecompilerNestedLayout(graph, LAYOUT_NAME);
    layout.setTaskMonitor(monitor);
    return layout;
  }

  @Override
  public AnvillGraphLayoutOptions createLayoutOptions(Options options) {
    DNLayoutOptions layoutOptions = new DNLayoutOptions();
    layoutOptions.registerOptions(options);
    return layoutOptions;
  }

  @Override
  public String getLayoutName() {
    return LAYOUT_NAME;
  }

  @Override
  public Icon getActionIcon() {
    return ICON;
  }

  @Override
  public int getPriorityLevel() {
    return 200;  // Above the others
  }
}
