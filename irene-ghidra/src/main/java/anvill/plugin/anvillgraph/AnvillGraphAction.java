package anvill.plugin.anvillgraph;

import docking.ActionContext;
import docking.action.DockingAction;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskListener;
import ghidra.util.task.TaskMonitor;

/**
 * An irene task synchronizes on a latch guarenteeing that at most one task is inflight at a time
 */
abstract class AnvillGraphAction extends DockingAction implements TaskListener {

  protected final AnvillGraphPlugin plugin;

  public AnvillGraphAction(AnvillGraphPlugin plugin, String name) {
    super(name, plugin.getName());
    this.plugin = plugin;
  }

  @Override
  public void actionPerformed(ActionContext context) {
    if (!plugin.tryAcquire()) {
      Msg.warn(this, "The IRENE decompiler is busy");
      return;
    }

    var tsk = new AnvillGraphTask(this, context);
    tsk.addTaskListener(this);
    new TaskLauncher(tsk);
  }

  public abstract void runInAction(TaskMonitor taskMonitor, ActionContext context);

  public void onTaskCompleted() {}

  @Override
  public void taskCompleted(Task task) {
    onTaskCompleted();
    plugin.release();
  }

  @Override
  public void taskCancelled(Task task) {
    plugin.release();
  }
}
