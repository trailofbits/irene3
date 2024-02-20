package anvill.plugin.anvillpatchgraph.action;

import anvill.plugin.anvillpatchgraph.AnvillGraphProvider;
import docking.ActionContext;
import ghidra.graph.viewer.actions.VisualGraphSatelliteActionContext;

public class AnvillGraphSatelliteViewerActionContext extends ActionContext
    implements VisualGraphSatelliteActionContext {
  public AnvillGraphSatelliteViewerActionContext(AnvillGraphProvider anvillGraphProvider) {
    super(anvillGraphProvider, null);
  }
}
