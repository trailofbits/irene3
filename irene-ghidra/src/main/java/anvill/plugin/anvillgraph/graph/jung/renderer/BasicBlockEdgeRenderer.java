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
package anvill.plugin.anvillgraph.graph.jung.renderer;


import anvill.plugin.anvillgraph.BBGraphOptions;
import anvill.plugin.anvillgraph.graph.*;
import edu.uci.ics.jung.graph.Graph;
import ghidra.graph.viewer.renderer.ArticulatedEdgeRenderer;
import java.awt.Color;

/**
 * A renderer used by the Function Graph API to provide additional edge coloring, as determined by
 * the {@link BBGraphOptions}.
 */
public class BasicBlockEdgeRenderer extends
    ArticulatedEdgeRenderer<BasicBlockVertex, BasicBlockEdge> {

  @Override
  public Color getBaseColor(Graph<BasicBlockVertex, BasicBlockEdge> g, BasicBlockEdge e) {
    BBGraphOptions options = getOptions(g);
    return options.getColor(e.getFlowType());
  }

  @Override
  public Color getHighlightColor(Graph<BasicBlockVertex, BasicBlockEdge> g, BasicBlockEdge e) {
    BBGraphOptions options = getOptions(g);
    return options.getHighlightColor(e.getFlowType());
  }

  private BBGraphOptions getOptions(Graph<BasicBlockVertex, BasicBlockEdge> g) {
    BasicBlockGraph fg = (BasicBlockGraph) g;
    return fg.getOptions();
  }
}
