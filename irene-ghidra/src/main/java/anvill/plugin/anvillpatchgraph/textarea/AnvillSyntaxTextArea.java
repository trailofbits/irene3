package anvill.plugin.anvillpatchgraph.textarea;

import javax.swing.JPopupMenu;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;

public class AnvillSyntaxTextArea extends RSyntaxTextArea {
  @Override
  public JPopupMenu getPopupMenu() {
    // unset popup menu
    return null;
  }
}
