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
package anvill.plugin.anvillgraph.graph;

import ghidra.graph.viewer.VisualEdge;
import ghidra.program.model.symbol.FlowType;

public interface BasicBlockEdge extends VisualEdge<BasicBlockVertex> {

  FlowType getFlowType();

  String getLabel();

  void setLabel(String label);

  /**
   * Set this edge's base alpha, which determines how much of the edge is visible/see through. 0 is
   * completely transparent.
   *
   * <P>This differs from {@link #setAlpha(double)} in that the latter is used for
   * temporary display effects.   This method is used to set the alpha value for the edge when it is
   * not part of a temporary display effect.
   *
   * @param alpha the alpha value
   */
  void setDefaultAlpha(double alpha);

  /**
   * Get this edge's base alpha, which determines how much of the edge is visible/see through. 0 is
   * completely transparent.
   *
   * <P>This differs from {@link #getAlpha()} in that the latter is used for
   * temporary display effects.   This method is used to set the alpha value for the edge when it is
   * not part of a temporary display effect.
   *
   * @return the alpha value
   */
  double getDefaultAlpha();

  @SuppressWarnings("unchecked")
  // Suppressing warning on the return type; we know our class is the right type
  @Override
  BasicBlockEdge cloneEdge(BasicBlockVertex start, BasicBlockVertex end);
}
