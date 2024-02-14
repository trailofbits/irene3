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
package anvill.plugin.anvillpatchgraph.layout;

import anvill.plugin.anvillpatchgraph.BBGraphOptions;
import anvill.plugin.anvillpatchgraph.graph.*;
import anvill.plugin.anvillpatchgraph.graph.jung.renderer.BasicBlockEdgeRenderer;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.layout.AbstractVisualGraphLayout;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.program.model.listing.Function;

/**
 * An abstract class that is the root for Function Graph layouts. It changes the type of the graph
 * returned to {@link BasicBlockGraph} and defines a clone method that takes in a Function Graph.
 */
public abstract class AbstractBBGraphLayout
    extends AbstractVisualGraphLayout<BasicBlockVertex, BasicBlockEdge>
    implements anvill.plugin.anvillpatchgraph.layout.BBGraphLayout {

  protected Function function;
  protected BBGraphOptions options;

  protected AbstractBBGraphLayout(BasicBlockGraph graph, String layoutName) {
    super(graph, layoutName);
    this.function = graph.getFunction();
    this.options = graph.getOptions();
  }

  protected abstract AbstractVisualGraphLayout<BasicBlockVertex, BasicBlockEdge>
      createClonedBBGraphLayout(BasicBlockGraph newGraph);

  @Override
  public BasicBlockGraph getVisualGraph() {
    return (BasicBlockGraph) getGraph();
  }

  @Override
  public AbstractVisualGraphLayout<BasicBlockVertex, BasicBlockEdge> createClonedLayout(
      VisualGraph<BasicBlockVertex, BasicBlockEdge> newGraph) {
    return createClonedBBGraphLayout((BasicBlockGraph) newGraph);
  }

  @Override
  public anvill.plugin.anvillpatchgraph.layout.BBGraphLayout cloneLayout(
      VisualGraph<BasicBlockVertex, BasicBlockEdge> newGraph) {
    VisualGraphLayout<BasicBlockVertex, BasicBlockEdge> clone = super.cloneLayout(newGraph);
    return (BBGraphLayout) clone;
  }

  @Override
  protected boolean isCondensedLayout() {
    return options.useCondensedLayout();
  }

  @Override
  public BasicBlockEdgeRenderer getEdgeRenderer() {
    return new BasicBlockEdgeRenderer();
  }
}
