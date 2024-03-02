package anvill.plugin;

import compiler.PatchCompiler;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskListener;
import ghidra.util.task.TaskMonitor;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.util.Objects;
import org.apache.commons.io.FileUtils;

class CompilerTask extends Task {

  private final PatchCompiler compiler;
  private final long uid;
  private final String module;

  private final PatchLowerInput pli;

  public CompilerTask(PatchCompiler compiler, long uid, String module, PatchLowerInput pli) {
    super("Compiler task");
    this.compiler = compiler;
    this.uid = uid;
    this.module = module;
    this.pli = pli;
  }

  @Override
  public void run(TaskMonitor taskMonitor) throws CancelledException {
    this.compiler.compileModule(this.module, uid, pli);
  }
}

public class CompileAction implements TaskListener {
  private final Component parent;
  private final File wdir;

  private final CompilerTask tsk;

  public CompileAction(
      Component parent, PatchCompiler compiler, long uid, String module, PatchLowerInput pli) {
    this.wdir = compiler.getWdir();
    this.parent = parent;
    this.tsk = new CompilerTask(compiler, uid, module, pli);
    tsk.addTaskListener(this);
    new TaskLauncher(tsk);
  }

  @Override
  public void taskCompleted(Task task) {
    var flchooser = new GhidraFileChooser(parent);
    flchooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
    flchooser.setTitle("Save Results to an Output Directory");
    var fl = flchooser.getSelectedFile();
    if (Objects.nonNull(fl)) {
      try {
        FileUtils.copyDirectoryToDirectory(this.wdir, fl);
      } catch (IOException ex) {
        Msg.error(this, "Failed to copy working directory for patch compiler");
      }
    }
  }

  @Override
  public void taskCancelled(Task task) {}
}
