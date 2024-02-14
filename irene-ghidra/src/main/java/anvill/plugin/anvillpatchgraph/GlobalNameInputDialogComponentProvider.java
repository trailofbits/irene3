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
package anvill.plugin.anvillpatchgraph;

import docking.DockingWindowManager;
import docking.widgets.label.GLabel;
import ghidra.bitpatterns.gui.InputDialogComponentProvider;
import ghidra.util.layout.PairLayout;
import javax.swing.JPanel;
import javax.swing.JTextField;

public class GlobalNameInputDialogComponentProvider extends InputDialogComponentProvider {
  private static final String GLOBAL_NAME_LABEL = "Global name ";

  private JTextField globalNameBox;

  /**
   * Create a dialog used for entering the name of a global symbol.
   *
   * @param title title String
   */
  public GlobalNameInputDialogComponentProvider(String title) {
    super(title);
    JPanel panel = createPanel();
    addWorkPanel(panel);
    addOKButton();
    addCancelButton();
    setDefaultButton(okButton);
    DockingWindowManager.showDialog(null, this);
  }

  @Override
  protected JPanel createPanel() {
    JPanel mainPanel = new JPanel();
    PairLayout pairLayout = new PairLayout();
    mainPanel.setLayout(pairLayout);

    mainPanel.add(new GLabel(GLOBAL_NAME_LABEL));
    globalNameBox = new JTextField();
    mainPanel.add(globalNameBox);

    return mainPanel;
  }

  public String getGlobalName() {
    return globalNameBox.getText();
  }
}
