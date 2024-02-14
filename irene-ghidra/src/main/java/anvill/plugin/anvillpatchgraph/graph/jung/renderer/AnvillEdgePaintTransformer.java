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
package anvill.plugin.anvillpatchgraph.graph.jung.renderer;

import anvill.plugin.anvillpatchgraph.BBGraphOptions;
import anvill.plugin.anvillpatchgraph.graph.BasicBlockEdge;
import com.google.common.base.Function;
import ghidra.program.model.symbol.FlowType;
import java.awt.Color;
import java.awt.Paint;

public class AnvillEdgePaintTransformer implements Function<BasicBlockEdge, Paint> {

  private BBGraphOptions options;

  public AnvillEdgePaintTransformer(BBGraphOptions options) {
    this.options = options;
  }

  @Override
  public Paint apply(BasicBlockEdge e) {
    FlowType flowType = e.getFlowType();
    Color color = options.getColor(flowType);
    return color;
  }
}
