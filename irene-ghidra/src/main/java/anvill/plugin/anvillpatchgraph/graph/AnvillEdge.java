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

import ghidra.graph.viewer.edge.AbstractVisualEdge;
import ghidra.program.model.symbol.FlowType;

public class AnvillEdge extends AbstractVisualEdge<BasicBlockVertex> implements BasicBlockEdge {

  private final FlowType flowType;

  private double defaultAlpha = 1D;
  private double alpha = defaultAlpha;

  private String edgeLabel = null;

  public AnvillEdge(BasicBlockVertex start, BasicBlockVertex end, FlowType flowType) {
    super(start, end);
    this.flowType = flowType;
  }

  public FlowType getFlowType() {
    return flowType;
  }

  @Override
  public String getLabel() {
    return edgeLabel;
  }

  @Override
  public void setLabel(String label) {
    edgeLabel = label;
  }

  @Override
  public void setAlpha(double alpha) {
    this.alpha = alpha;
  }

  @Override
  public double getAlpha() {
    return alpha;
  }

  @Override
  public void setDefaultAlpha(double alpha) {
    defaultAlpha = alpha;
    this.alpha = alpha;
  }

  @Override
  public double getDefaultAlpha() {
    return defaultAlpha;
  }

  @SuppressWarnings("unchecked")
  // Suppressing warning on the return type; we know our class is the right type
  @Override
  public AnvillEdge cloneEdge(BasicBlockVertex start, BasicBlockVertex end) {
    return new AnvillEdge(start, end, flowType);
  }
}
