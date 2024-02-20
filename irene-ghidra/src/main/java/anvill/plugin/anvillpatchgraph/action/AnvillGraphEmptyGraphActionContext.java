package anvill.plugin.anvillpatchgraph.action;

import anvill.plugin.anvillpatchgraph.AnvillGraphProvider;
import ghidra.app.context.ProgramActionContext;
import ghidra.graph.viewer.actions.VisualGraphActionContext;

public class AnvillGraphEmptyGraphActionContext extends ProgramActionContext
    implements VisualGraphActionContext {
  public AnvillGraphEmptyGraphActionContext(AnvillGraphProvider anvillGraphProvider) {
    super(anvillGraphProvider, anvillGraphProvider.getProgram());
  }

  @Override
  public boolean shouldShowSatelliteActions() {
    return true;
  }
}
