package anvill.plugin.anvillpatchgraph.action;

import anvill.plugin.anvillpatchgraph.AnvillGraphProvider;
import anvill.plugin.anvillpatchgraph.graph.BasicBlockVertex;
import ghidra.app.context.ProgramActionContext;
import ghidra.graph.viewer.actions.VisualGraphActionContext;
import java.util.Set;

public class AnvillGraphValidGraphActionContext extends ProgramActionContext
    implements AnvillGraphValidGraphActionContextIf, VisualGraphActionContext {
  private final Set<BasicBlockVertex> selectedVertices;

  public AnvillGraphValidGraphActionContext(
      AnvillGraphProvider anvillGraphProvider, Set<BasicBlockVertex> selectedVertices) {
    super(anvillGraphProvider, anvillGraphProvider.getProgram());
    this.selectedVertices = selectedVertices;
  }

  @Override
  public Set<BasicBlockVertex> getSelectedVertices() {
    return selectedVertices;
  }
}
