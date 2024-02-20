package anvill.plugin.anvillpatchgraph.action;

import anvill.plugin.anvillpatchgraph.AnvillGraphProvider;
import anvill.plugin.anvillpatchgraph.graph.BasicBlockVertex;
import ghidra.app.context.ProgramActionContext;
import java.util.Set;

public class AnvillGraphUneditableVertexLocationActionContext extends ProgramActionContext
    implements AnvillGraphVertexLocationContextIf {

  private final VertexActionContextInfo vertexInfo;

  public AnvillGraphUneditableVertexLocationActionContext(
      AnvillGraphProvider anvillGraphProvider, VertexActionContextInfo vertexInfo) {
    super(anvillGraphProvider, anvillGraphProvider.getProgram());

    if (vertexInfo == null) {
      throw new NullPointerException("VertexActionContextInfo cannot be null");
    }

    this.vertexInfo = vertexInfo;
  }

  @Override
  public Set<BasicBlockVertex> getSelectedVertices() {
    return vertexInfo.getSelectedVertices();
  }

  @Override
  public BasicBlockVertex getVertex() {
    return vertexInfo.getActiveVertex();
  }

  @Override
  public VertexActionContextInfo getVertexInfo() {
    return vertexInfo;
  }
}
