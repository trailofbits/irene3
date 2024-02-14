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
package anvill.plugin.anvillpatchgraph.graph;

import anvill.plugin.anvillpatchgraph.BBGraphOptions;
import anvill.plugin.anvillpatchgraph.layout.BBGraphLayout;
import ghidra.graph.graphs.FilteringVisualGraph;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class BasicBlockGraph
    extends FilteringVisualGraph<
        BasicBlockVertex, anvill.plugin.anvillpatchgraph.graph.BasicBlockEdge> {

  private BBGraphLayout layout;
  private Function function;
  private BBGraphOptions options;

  public BasicBlockGraph(Function function) {
    this.function = function;
  }

  @Override
  public BBGraphLayout getLayout() {
    return layout;
  }

  @Override
  public BasicBlockGraph copy() {
    BasicBlockGraph newGraph = new BasicBlockGraph(getFunction());

    for (BasicBlockVertex v : vertices.keySet()) {
      newGraph.addVertex(v);
    }

    for (BasicBlockEdge e : edges.keySet()) {
      newGraph.addEdge(e);
    }

    BBGraphLayout originalLayout = getLayout();
    BBGraphLayout newLayout = originalLayout.cloneLayout(newGraph);
    newGraph.setLayout(newLayout);
    newLayout.setSize(originalLayout.getSize());

    newGraph.setOptions(getOptions());
    return newGraph;
  }

  public void setLayout(BBGraphLayout layout) {
    this.layout = layout;
  }

  public Function getFunction() {
    return function;
  }

  /**
   * TODO: This could be implemented more efficiently
   *
   * @param addr Address to get vertex
   * @return matching vertex or null
   */
  public BasicBlockVertex getVertexAtAddr(Address addr) {
    return vertices.keySet().stream().filter(v -> v.containsAddress(addr)).findFirst().orElse(null);
  }

  public BBGraphOptions getOptions() {
    return options;
  }

  public void setOptions(BBGraphOptions options) {
    this.options = options;
  }
}
