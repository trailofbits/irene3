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

import anvill.PatchLangGrpcClient;
import anvill.plugin.CompileAction;
import anvill.plugin.PatchLowerInputWindow;
import anvill.plugin.anvillpatchgraph.AnvillPatchInfo;
import anvill.plugin.anvillpatchgraph.parser.AntlrCParser;
import anvill.plugin.anvillpatchgraph.textarea.AnvillSyntaxTextArea;
import compiler.DockerCommandLineDriver;
import compiler.PatchCompiler;
import docking.ActionContext;
import docking.GenericHeader;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import generic.theme.GColor;
import ghidra.framework.preferences.Preferences;
import ghidra.graph.viewer.vertex.AbstractVisualVertex;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.Program;
import ghidra.util.MathUtilities;
import ghidra.util.Msg;
import io.grpc.StatusRuntimeException;
import irene3.server.PatchService;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.beans.PropertyChangeListener;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Objects;
import java.util.Optional;
import javax.swing.*;
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
  private final long size;
  private JPanel mainPanel = new JPanel(new BorderLayout());
  private final RSyntaxTextArea textArea;
  private final GenericHeader genericHeader;
  private boolean editable = false;
  public static final ImageIcon LOCK_IMAGE;
  public static final ImageIcon UNLOCK_IMAGE;
  public static final ImageIcon COMPILE_IMAGE;
  private int maxWidth = 500;
  private String oldPatchCode;
  private PatchLangGrpcClient patchGrpcClient;
  private DockingAction editLockAction;
  private DockingAction compileAction;

  private Optional<String> last_patched_module;

  static {
    LOCK_IMAGE = ResourceManager.loadImage("images/lock.gif");
    UNLOCK_IMAGE = ResourceManager.loadImage("images/unlock.gif");
    COMPILE_IMAGE = ResourceManager.loadImage("images/editbytes.gif");
  }

  public AnvillVertex(CodeBlock block, AnvillPatchInfo.Patch patch, PatchLangGrpcClient client) {
    patchGrpcClient = client;
    name = patch.getAddress();
    program = block.getModel().getProgram();
    AddressFactory addressFactory = program.getAddressFactory();
    address = addressFactory.getAddress(patch.getAddress());
    size = patch.getSize();
    Address maxAddress =
        addressFactory.getAddress(
            address.getAddressSpace().getSpaceID(),
            address.getOffset() + Long.max(patch.getSize() - 1, 0));
    addressSetView = new AddressSet(address, maxAddress);
    this.patch = patch;
    this.last_patched_module = Optional.empty();

    textArea = new AnvillSyntaxTextArea();
    textArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_C);
    textArea.setEditable(editable);
    textArea.setPreferredSize(null);
    textArea.setTabsEmulated(false);
    textArea.setLineWrap(false);

    textArea.setText(patch.getCode());
    oldPatchCode = patch.getCode();
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
    this.editable = editable;

    textArea.setEditable(editable);
    textArea.getCaret().setVisible(editable);
    textArea.getCaret().setSelectionVisible(editable);

    editLockAction.setDescription(editable ? "Lock Editing" : "Unlock Editing");
    editLockAction.getToolBarData().setIcon(editable ? UNLOCK_IMAGE : LOCK_IMAGE);
    genericHeader.update();
  }

  @Override
  public boolean isEditable() {
    return editable;
  }

  Optional<PatchService.PatchResponse> applyPatch(
      PatchLangGrpcClient client, PatchService.PatchRequest newPatch) {
    try {
      return client.applyPatch(newPatch);
    } catch (StatusRuntimeException e) {
      Msg.error(this, "PatchLang appyPatch RPC failed: " + e.getStatus());
      return Optional.empty();
    }
  }

  public void edit_toggle() {
    String newPatchCode = getText();
    // User is trying to lock/submit modifications to the patch
    if (editable && !Objects.equals(oldPatchCode, newPatchCode)) {
      Optional<PatchService.PatchResponse> maybeResp =
          applyPatch(
              patchGrpcClient,
              PatchService.PatchRequest.newBuilder()
                  .setUid(getPatch().getUid())
                  .setNewCode(newPatchCode)
                  .build());
      if (!maybeResp.isPresent()) {
        Msg.showError(
            this,
            null,
            "Could not apply patch",
            "Reverting. Could not apply new patch code.",
            // Wrap in exception to get better formatting in message box
            new Exception(newPatchCode));
        setText(oldPatchCode);
        return;
      }
      var resp = maybeResp.get();
      oldPatchCode = resp.getNewCode();
      setText(oldPatchCode);

      String module = resp.getPatchedModule();
      saveModule(module);
      this.last_patched_module = Optional.of(module);
    }
    editable = !editable;
    setEditable(editable);
  }

  private void saveModule(String module) {
    GhidraFileChooser chooser = new GhidraFileChooser(mainPanel);
    chooser.setTitle("Save Patch Module File");
    File saveFile = chooser.getSelectedFile();
    if (saveFile == null) {
      return;
    }
    boolean exists = saveFile.exists();
    if (exists
        && OptionDialog.showYesNoDialog(
                mainPanel,
                "Save PatchLang Module",
                "Do you want to OVERWRITE the following file:\n" + saveFile.getName())
            != OptionDialog.OPTION_ONE) {
      return;
    }
    try {
      PrintWriter writer = new PrintWriter(new FileWriter(saveFile));
      writer.println(module);
      writer.close();
    } catch (IOException e) {
      Msg.showError(this, mainPanel, "Error Saving File As...", e.getMessage());
    }
  }

  private void setupActions() {
    editLockAction =
        new DockingAction("Edit", genericHeader.getClass().getName()) {
          @Override
          public void actionPerformed(ActionContext context) {
            edit_toggle();
            setDescription(editable ? "Lock Editing" : "Unlock Editing");
            getToolBarData().setIcon(editable ? UNLOCK_IMAGE : LOCK_IMAGE);
          }
        };
    editLockAction.setDescription(editable ? "Lock Editing" : "Unlock Editing");
    editLockAction.setToolBarData(new ToolBarData(editable ? UNLOCK_IMAGE : LOCK_IMAGE));

    compileAction =
        new DockingAction("Compile", genericHeader.getClass().getName()) {
          @Override
          public void actionPerformed(ActionContext context) {
            var exePath = program.getExecutablePath();
            if (new File(exePath).exists()) {
              Preferences.setProperty(PatchLowerInputWindow.STARTING_DIR_PROP, exePath);
            }
            var window = new PatchLowerInputWindow(null);
            var input = window.askUser();
            // TODO: Call the binaries with input
            Msg.info(this, "Compiling... " + input);
            PatchCompiler compiler;
            try {
              compiler = new PatchCompiler(new DockerCommandLineDriver());
            } catch (IOException e) {
              throw new RuntimeException(e);
            }
            if (input.isPresent() && AnvillVertex.this.last_patched_module.isPresent()) {
              new CompileAction(
                  AnvillVertex.this.mainPanel,
                  compiler,
                  patch.getUid(),
                  AnvillVertex.this.last_patched_module.get(),
                  input.get());
            }
          }
        };
    compileAction.setToolBarData(new ToolBarData(COMPILE_IMAGE));
    // TODO: Only enable when editing or content has changed
    compileAction.setEnabled(true);
    compileAction.setDescription("Compile Patch Code");

    genericHeader.actionAdded(compileAction);
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

  void setText(String text) {
    textArea.setText(text);
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
  public AddressSetView getAddresses() {
    return addressSetView;
  }

  @Override
  public long getSize() {
    return size;
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
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    AnvillVertex that = (AnvillVertex) o;
    return size == that.size && Objects.equals(name, that.name);
  }

  @Override
  public int hashCode() {
    return Objects.hash(name, size);
  }
}
