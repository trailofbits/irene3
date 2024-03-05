package anvill.plugin;

import docking.widgets.filechooser.GhidraFileChooserPanel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.nio.file.Path;
import java.util.Objects;
import java.util.Optional;
import javax.swing.*;

/**
 * A class that can show a dialog window to allow the user to enter information about patch
 * lowering.
 */
public class PatchLowerInputWindow {

  private JDialog dialog;
  private JTextField featuresField;
  private JTextField cpuField;
  private JTextField backendField;

  private JTextField detourLocationField;
  private PatchLowerInput userInput;
  /** Property name for setting the starting directory for file chooser */
  public static final String STARTING_DIR_PROP = "PatchLowering Input Binary";

  private GhidraFileChooserPanel orig_bin;

  public PatchLowerInputWindow(Frame parent) {
    initializeUI(parent);
  }

  private void initializeUI(Frame parent) {
    dialog = new JDialog(parent, "User Input", true);
    dialog.setLayout(new GridLayout(3, 1));

    var featuresField = new JTextField();
    cpuField = new JTextField();
    backendField = new JTextField();
    detourLocationField = new JTextField();

    JButton okButton = new JButton("OK");
    JButton cancelButton = new JButton("Cancel");

    this.orig_bin =
        new GhidraFileChooserPanel(
            "Select Input Binary", STARTING_DIR_PROP, "", false, GhidraFileChooserPanel.INPUT_MODE);

    var text_inputs = new JPanel(new GridLayout(4, 2));

    text_inputs.add(new JLabel("Features:"));
    text_inputs.add(featuresField);
    text_inputs.add(new JLabel("CPU:"));
    text_inputs.add(cpuField);
    text_inputs.add(new JLabel("Backend:"));
    text_inputs.add(backendField);
    text_inputs.add(new JLabel("Detour Location:"));
    text_inputs.add(this.detourLocationField);
    dialog.add(text_inputs);
    dialog.add(orig_bin);

    var submit_comp = new JPanel(new GridLayout(1, 2));
    submit_comp.add(okButton);
    submit_comp.add(cancelButton);
    dialog.add(submit_comp);

    okButton.addActionListener(
        new ActionListener() {
          @Override
          public void actionPerformed(ActionEvent e) {
            userInput =
                new PatchLowerInput(
                    featuresField.getText(),
                    cpuField.getText(),
                    backendField.getText(),
                    Path.of(orig_bin.getFileName()).toFile(),
                    detourLocationField.getText());

            dialog.dispose();
          }
        });

    cancelButton.addActionListener(
        new ActionListener() {
          @Override
          public void actionPerformed(ActionEvent e) {
            dialog.dispose();
          }
        });

    dialog.pack();
    dialog.setLocationRelativeTo(parent);
  }

  public Optional<PatchLowerInput> askUser() {
    userInput = null;
    dialog.setVisible(true);
    if (Objects.nonNull(this.userInput)) {
      return Optional.of(userInput);
    } else {
      return Optional.empty();
    }
  }
}
