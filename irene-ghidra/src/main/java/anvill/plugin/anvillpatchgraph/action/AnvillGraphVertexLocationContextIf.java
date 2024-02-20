package anvill.plugin.anvillpatchgraph.action;

import anvill.plugin.anvillpatchgraph.graph.BasicBlockVertex;
import ghidra.graph.viewer.actions.VisualGraphVertexActionContext;

public interface AnvillGraphVertexLocationContextIf
    extends AnvillGraphValidGraphActionContextIf, VisualGraphVertexActionContext<BasicBlockVertex> {

  @Override
  public BasicBlockVertex getVertex();

  public VertexActionContextInfo getVertexInfo();
}
