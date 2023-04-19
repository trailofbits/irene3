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

import anvill.plugin.anvillgraph.AnvillGraphProvider;
import anvill.plugin.anvillgraph.AnvillPatchInfo;
import docking.ActionContext;
import docking.GenericHeader;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.graph.viewer.vertex.DockingVisualVertex;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import java.awt.Color;
import java.awt.Component;
import javax.swing.ImageIcon;
import javax.swing.JTextArea;
import resources.ResourceManager;

public class AnvillVertex extends DockingVisualVertex implements BasicBlockVertex {

  private final AnvillPatchInfo.Patch patch;
  private final Program program;
  private final Address address;
  private final AddressSetView addressSetView;
  private final AnvillGraphProvider provider;
  private boolean editable = false;
  public static final ImageIcon LOCK_IMAGE;
  public static final ImageIcon UNLOCK_IMAGE;

  static {
    LOCK_IMAGE = ResourceManager.loadImage("images/lock.gif");
    UNLOCK_IMAGE = ResourceManager.loadImage("images/unlock.gif");
  }

  public AnvillVertex(AnvillGraphProvider provider, CodeBlock block, AnvillPatchInfo.Patch patch) {
    super(block.getFirstStartAddress().toString());
    this.provider = provider;
    address = block.getFirstStartAddress();
    addressSetView = block;
    program = block.getModel().getProgram();
    this.patch = patch;

    init();
    setupActions();
  }

  /** Set the necessary things to make this properly viewable */
  public void init() {
    // High number to prevent horizontal text cutoff
    setMaxWidth(5000);

    // No wrapping of text
    JTextArea textArea = getTextArea();
    textArea.setEditable(editable);
    textArea.setPreferredSize(null);
    textArea.setLineWrap(false);
    textArea.setBackground(Color.WHITE);
    textArea.setCaretColor(Color.BLACK);
    textArea.setText(patch.getCode());
  }

  private void setupActions() {
    // This is always the header
    GenericHeader header = (GenericHeader) getComponent().getComponent(0);

    DockingAction editLockAction =
        new DockingAction("Edit", header.getClass().getName()) {
          @Override
          public void actionPerformed(ActionContext context) {
            editable = !editable;
            getTextArea().setEditable(editable);
            setDescription(editable ? "Lock Editing" : "Unlock Editing");
            getToolBarData().setIcon(editable ? UNLOCK_IMAGE : LOCK_IMAGE);
          }
        };
    editLockAction.setDescription(editable ? "Lock Editing" : "Unlock Editing");
    editLockAction.setToolBarData(new ToolBarData(editable ? UNLOCK_IMAGE : LOCK_IMAGE));

    header.actionAdded(editLockAction);
    header.update();
  }

  @Override
  public void setFocused(boolean focused) {
    super.setFocused(focused);
    if (focused) {
      provider.goTo(new ProgramLocation(getProgram(), address));
    }
  }

  @Override
  public boolean isGrabbable(Component c) {
    if (c == getTextArea() && editable) {
      return false;
    }
    return true;
  }

  public AnvillPatchInfo.Patch getPatch() {
    return patch;
  }

  public void setEditable() {
    getTextArea().setEditable(true);
  }

  @Override
  public Program getProgram() {
    return program;
  }

  @Override
  public Address getVertexAddress() {
    return address;
  }

  @Override
  public boolean containsAddress(Address address) {
    return addressSetView.contains(address);
  }
}
