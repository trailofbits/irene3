package anvill.plugin.anvillpatchgraph;

import docking.ActionContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

class AnvillGraphTask extends Task {
  AnvillGraphAction parent;
  ActionContext context;

  public AnvillGraphTask(AnvillGraphAction parent, ActionContext context) {
    super("Anvill graph task");
    this.parent = parent;
    this.context = context;
  }

  @Override
  public void run(TaskMonitor taskMonitor) throws CancelledException {
    this.parent.runInAction(taskMonitor, this.context);
  }
}
