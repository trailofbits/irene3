package anvill.plugin.anvillpatchgraph.action;

import anvill.plugin.anvillpatchgraph.graph.BasicBlockVertex;
import java.util.Set;

public interface AnvillGraphValidGraphActionContextIf {
  public Set<BasicBlockVertex> getSelectedVertices();
}
