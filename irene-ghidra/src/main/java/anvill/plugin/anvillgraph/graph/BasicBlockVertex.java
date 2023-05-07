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

import ghidra.graph.viewer.VisualVertex;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import javax.swing.JTextArea;

/** A vertex that represents a Basic Block in a control-flow graph */
public interface BasicBlockVertex extends VisualVertex {

  public abstract Program getProgram();

  public abstract Address getVertexAddress();

  public abstract boolean containsAddress(Address address);

  public abstract void setEditable(boolean editable);

  public abstract String getText();

  public abstract JTextArea getTextArea();
}
