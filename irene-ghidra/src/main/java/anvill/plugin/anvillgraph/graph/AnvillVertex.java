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

import anvill.plugin.anvillgraph.AnvillPatchInfo;
import anvill.plugin.anvillgraph.parser.AntlrCParser;
import anvill.plugin.anvillgraph.textarea.AnvillSyntaxTextArea;
import docking.ActionContext;
import docking.GenericHeader;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import generic.theme.GColor;
import ghidra.graph.viewer.vertex.AbstractVisualVertex;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.Program;
import ghidra.util.MathUtilities;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.KeyboardFocusManager;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.beans.PropertyChangeListener;
import javax.swing.ImageIcon;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rsyntaxtextarea.SyntaxScheme;
import org.fife.ui.rsyntaxtextarea.Token;
import org.fife.ui.rtextarea.RTextScrollPane;
import resources.ResourceManager;

public class AnvillVertex extends AbstractVisualVertex implements BasicBlockVertex {

  private final AnvillPatchInfo.Patch patch;
  private final Program program;
  private final Address address;
  private final AddressSetView addressSetView;
  private final String name;
  private JPanel mainPanel = new JPanel(new BorderLayout());
  private final RSyntaxTextArea textArea;
  private final GenericHeader genericHeader;
  private boolean editable = false;
  public static final ImageIcon LOCK_IMAGE;
  public static final ImageIcon UNLOCK_IMAGE;
  private int maxWidth = 500;

  static {
    LOCK_IMAGE = ResourceManager.loadImage("images/lock.gif");
    UNLOCK_IMAGE = ResourceManager.loadImage("images/unlock.gif");
  }

  public AnvillVertex(CodeBlock block, AnvillPatchInfo.Patch patch) {
    name = patch.getAddress();
    program = block.getModel().getProgram();
    AddressFactory addressFactory = program.getAddressFactory();
    address = addressFactory.getAddress(patch.getAddress());
    Address maxAddress =
        addressFactory.getAddress(
            address.getAddressSpace().getSpaceID(), address.getOffset() + patch.getSize());
    addressSetView = new AddressSet(address, maxAddress);
    this.patch = patch;

    textArea = new AnvillSyntaxTextArea();
    textArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_C);
    textArea.setEditable(editable);
    textArea.setPreferredSize(null);
    textArea.setTabsEmulated(false);
    textArea.setLineWrap(false);

    textArea.setText(patch.getCode());
    setupTheme();

    PropertyChangeListener[] listeners = textArea.getPropertyChangeListeners();
    for (PropertyChangeListener l : listeners) {

      // the AquaCaret does not remove itself as a listener
      if (l.getClass().getSimpleName().contains("AquaCaret")) {
        textArea.removePropertyChangeListener(l);
      }
    }

    genericHeader =
        new GenericHeader() {
          // overridden to prevent excessive title bar width for long names
          @Override
          public Dimension getPreferredSize() {
            Dimension preferredSize = super.getPreferredSize();
            int width = textArea.getPreferredSize().width;
            int preferredWidth = MathUtilities.clamp(width, width, maxWidth);
            if (preferredWidth <= 0) {
              return preferredSize;
            }

            int toolBarWidth = getToolBarWidth();
            int minimumGrabArea = 60;
            int minimumWidth = minimumGrabArea + toolBarWidth;
            preferredSize.width = MathUtilities.clamp(preferredWidth, minimumWidth, maxWidth);
            return preferredSize;
          }
        };
    genericHeader.setTitle(name);
    genericHeader.setNoWrapToolbar(true);
    mainPanel.addKeyListener(
        new KeyListener() {

          @Override
          public void keyTyped(KeyEvent e) {
            if (!textArea.isEditable()) {
              return;
            }

            KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
            kfm.redispatchEvent(textArea, e);
            e.consume(); // consume all events; signal that our text area will handle them
          }

          @Override
          public void keyReleased(KeyEvent e) {

            if (!textArea.isEditable()) {
              return;
            }

            KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
            kfm.redispatchEvent(textArea, e);
            e.consume(); // consume all events; signal that our text area will handle them
          }

          @Override
          public void keyPressed(KeyEvent e) {

            if (!textArea.isEditable()) {
              return;
            }

            KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
            kfm.redispatchEvent(textArea, e);
            e.consume(); // consume all events; signal that our text area will handle them
          }
        });
    var sp = new RTextScrollPane(textArea);
    genericHeader.setComponent(sp);
    mainPanel.add(genericHeader, BorderLayout.NORTH);
    mainPanel.add(sp, BorderLayout.CENTER);

    // note: disable focus traversal keys to ensure tab key does not get consumed
    mainPanel.setFocusTraversalKeysEnabled(false);

    // this MUST be added after adding to the main panel
    textArea.addParser(new AntlrCParser());
    setupActions();
  }

  private void setupTheme() {
    textArea.setBackground(new GColor("color.bg.decompiler"));
    textArea.setCaretColor(new GColor("color.fg.decompiler"));
    textArea.setForeground(new GColor("color.fg.decompiler"));

    SyntaxScheme scheme = textArea.getSyntaxScheme();
    scheme.getStyle(Token.RESERVED_WORD).foreground = new GColor("color.fg.decompiler.keyword");
    scheme.getStyle(Token.DATA_TYPE).foreground = new GColor("color.fg.decompiler.type");
    scheme.getStyle(Token.LITERAL_CHAR).foreground = new GColor("color.fg.decompiler.constant");
    scheme.getStyle(Token.LITERAL_BOOLEAN).foreground = new GColor("color.fg.decompiler.constant");
    scheme.getStyle(Token.LITERAL_BACKQUOTE).foreground =
        new GColor("color.fg.decompiler.constant");
    scheme.getStyle(Token.LITERAL_NUMBER_FLOAT).foreground =
        new GColor("color.fg.decompiler.constant");
    scheme.getStyle(Token.LITERAL_NUMBER_DECIMAL_INT).foreground =
        new GColor("color.fg.decompiler.constant");
    scheme.getStyle(Token.LITERAL_NUMBER_HEXADECIMAL).foreground =
        new GColor("color.fg.decompiler.constant");
    scheme.getStyle(Token.FUNCTION).foreground = new GColor("color.fg.decompiler.function.name");
    scheme.getStyle(Token.COMMENT_MARKUP).foreground = new GColor("color.fg.decompiler.comment");
    scheme.getStyle(Token.COMMENT_EOL).foreground = new GColor("color.fg.decompiler.comment");
    scheme.getStyle(Token.COMMENT_KEYWORD).foreground = new GColor("color.fg.decompiler.comment");
    scheme.getStyle(Token.COMMENT_MULTILINE).foreground = new GColor("color.fg.decompiler.comment");
    scheme.getStyle(Token.COMMENT_DOCUMENTATION).foreground =
        new GColor("color.fg.decompiler.comment");
    scheme.getStyle(Token.VARIABLE).foreground = new GColor("color.fg.decompiler.variable");
    scheme.getStyle(Token.SEPARATOR).foreground = new GColor("color.fg.decompiler");
    scheme.getStyle(Token.ERROR_CHAR).foreground = new GColor("color.fg.decompiler.error");
    scheme.getStyle(Token.OPERATOR).foreground = new GColor("color.fg.decompiler");
  }

  @Override
  public void setEditable(boolean editable) {
    textArea.setEditable(editable);
    textArea.getCaret().setVisible(editable);
    textArea.getCaret().setSelectionVisible(editable);
  }

  private void setupActions() {
    DockingAction editLockAction =
        new DockingAction("Edit", genericHeader.getClass().getName()) {
          @Override
          public void actionPerformed(ActionContext context) {
            editable = !editable;
            setEditable(editable);
            setDescription(editable ? "Lock Editing" : "Unlock Editing");
            getToolBarData().setIcon(editable ? UNLOCK_IMAGE : LOCK_IMAGE);
          }
        };
    editLockAction.setDescription(editable ? "Lock Editing" : "Unlock Editing");
    editLockAction.setToolBarData(new ToolBarData(editable ? UNLOCK_IMAGE : LOCK_IMAGE));

    genericHeader.actionAdded(editLockAction);
    genericHeader.update();
  }

  @Override
  public JComponent getComponent() {
    return mainPanel;
  }

  @Override
  public void setFocused(boolean focused) {
    super.setFocused(focused);
    if (textArea.isEditable()) {
      textArea.getCaret().setVisible(focused);
    }
  }

  @Override
  public void setSelected(boolean selected) {
    super.setSelected(selected);
    genericHeader.setSelected(selected);
  }

  @Override
  public void dispose() {
    genericHeader.dispose();
  }

  @Override
  public boolean isGrabbable(Component c) {
    if (c == textArea && editable) {
      return false;
    }
    return true;
  }

  public AnvillPatchInfo.Patch getPatch() {
    return patch;
  }

  @Override
  public JTextArea getTextArea() {
    return textArea;
  }

  @Override
  public String getText() {
    return textArea.getText();
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

  @Override
  public String toString() {
    return name;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((name == null) ? 0 : name.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    AnvillVertex other = (AnvillVertex) obj;
    if (name == null) {
      if (other.name != null) {
        return false;
      }
    } else if (!name.equals(other.name)) {
      return false;
    }
    return true;
  }
}
