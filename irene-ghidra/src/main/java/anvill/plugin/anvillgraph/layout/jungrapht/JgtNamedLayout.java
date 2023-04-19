/* ###
 * Adapted from upstream Ghidra 10.1.5
 *
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package anvill.plugin.anvillgraph.layout.jungrapht;

import anvill.plugin.anvillgraph.graph.*;
import anvill.plugin.anvillgraph.layout.AbstractBBGraphLayout;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.layout.*;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.util.exception.CancelledException;
import java.awt.Dimension;
import java.awt.geom.Point2D;
import java.util.*;
import java.util.function.Function;
import java.util.function.Predicate;
import org.jgrapht.graph.AbstractBaseGraph;
import org.jgrapht.graph.DefaultGraphType;
import org.jungrapht.visualization.layout.algorithms.LayoutAlgorithm;
import org.jungrapht.visualization.layout.algorithms.util.EdgeArticulationFunctionSupplier;
import org.jungrapht.visualization.layout.model.LayoutModel;
import org.jungrapht.visualization.layout.model.Point;

/**
 * A layout that delegates work to the Jung layout specified in the constructor.
 */
public class JgtNamedLayout extends AbstractBBGraphLayout {

  private static Function<BasicBlockEdge, List<Point>> DUMMY_ARTICULATOR = e -> Collections.emptyList();

  JgtNamedLayout(BasicBlockGraph graph, String layoutName) {
    super(graph, layoutName);
  }

  @Override
  protected AbstractVisualGraphLayout<BasicBlockVertex, BasicBlockEdge> createClonedBBGraphLayout(
      BasicBlockGraph newGraph) {
    return new JgtNamedLayout(newGraph, layoutName);
  }

  @Override
  protected Point2D getVertexLocation(BasicBlockVertex v, Column col, Row<BasicBlockVertex> row,
      java.awt.Rectangle bounds) {
    return getCenteredVertexLocation(v, col, row, bounds);
  }

  @Override
  protected GridLocationMap<BasicBlockVertex, BasicBlockEdge> performInitialGridLayout(
      VisualGraph<BasicBlockVertex, BasicBlockEdge> visualGraph) throws CancelledException {

    BasicBlockEdgeComparator edgeComparator = new BasicBlockEdgeComparator();
    Predicate<BasicBlockEdge> favoredEdgePredicate = getFavoredEdgePredicate();
    Predicate<BasicBlockVertex> rootPredicate = null;

    JgtLayoutFactory<BasicBlockVertex, BasicBlockEdge> layoutProvider =
        new JgtLayoutFactory<>(edgeComparator, favoredEdgePredicate, rootPredicate);

    LayoutAlgorithm<BasicBlockVertex> layout = layoutProvider.getLayout(layoutName);

    AnvillTempGraph jGraph = buildGraph(visualGraph);

    VisualGraphLayout<BasicBlockVertex, BasicBlockEdge> vgLayout = visualGraph.getLayout();
    Dimension layoutSize = vgLayout.getSize();

    LayoutModel<BasicBlockVertex> layoutModel =
        LayoutModel.<BasicBlockVertex>builder()
            .graph(jGraph)
            .size(layoutSize.width, layoutSize.height)
            .build();

    layoutModel.accept(layout);

    GridLocationMap<BasicBlockVertex, BasicBlockEdge> grid = convertToGrid(jGraph, layoutModel,
        layout);

    return grid;
  }

  private GridLocationMap<BasicBlockVertex, BasicBlockEdge> convertToGrid(
      AnvillTempGraph jGraph,
      LayoutModel<BasicBlockVertex> layoutModel,
      LayoutAlgorithm<BasicBlockVertex> layoutAlgorithm)
      throws CancelledException {

    GridLocationMap<BasicBlockVertex, BasicBlockEdge> grid = new GridLocationMap<>();

    Map<Double, Integer> columns = new TreeMap<>();
    Map<Double, Integer> rows = new TreeMap<>();

    Set<BasicBlockVertex> jungVertices = jGraph.vertexSet();
    for (BasicBlockVertex fgVertex : jungVertices) {
      monitor.checkCanceled();

      Point point = layoutModel.get(fgVertex);
      columns.put(point.x, 0);
      rows.put(point.y, 0);
    }

    Function<BasicBlockEdge, List<Point>> articulator = getArticulator(layoutAlgorithm);
    Set<BasicBlockEdge> edges = jGraph.edgeSet();
    for (BasicBlockEdge fgEdge : edges) {
      monitor.checkCanceled();

      List<Point> ariculations = articulator.apply(fgEdge);
      for (Point point : ariculations) {
        columns.put(point.x, 0);
        rows.put(point.y, 0);
      }
    }

    // translate the real coordinates to grid coordinates (row and column indices)
    int counter = 0;
    for (Double x : columns.keySet()) {
      monitor.checkCanceled();
      columns.put(x, counter++);
    }

    counter = 0;
    for (Double y : rows.keySet()) {
      monitor.checkCanceled();
      rows.put(y, counter++);
    }

    jungVertices = jGraph.vertexSet();
    for (BasicBlockVertex fgVertex : jungVertices) {
      monitor.checkCanceled();

      Point point = layoutModel.get(fgVertex);
      grid.set(fgVertex, rows.get(point.y), columns.get(point.x));
    }

    edges = jGraph.edgeSet();
    for (BasicBlockEdge fgEdge : edges) {
      monitor.checkCanceled();

      List<java.awt.Point> newPoints = new ArrayList<>();

      List<Point> articulations = articulator.apply(fgEdge);
      for (Point point : articulations) {

        Integer col = columns.get(point.x);
        Integer row = rows.get(point.y);
        newPoints.add(new java.awt.Point(col, row));
      }

      // The jung layout will provide articulations at the vertex points.   We do not want to
      // use these values, since we may move the vertices during layout.  Our BasicBlockEdgeRenderer will
      // connect the articulation endpoints to the vertices when drawing, so we do not need
      // these points provided by jung.
      if (!articulations.isEmpty()) {
        newPoints.remove(0);
        newPoints.remove(newPoints.size() - 1);
      }

      grid.setArticulations(fgEdge, newPoints);
    }

    return grid;
  }

  private Function<BasicBlockEdge, List<Point>> getArticulator(
      LayoutAlgorithm<BasicBlockVertex> layout) {

    if (layout instanceof EdgeArticulationFunctionSupplier) {
      @SuppressWarnings("unchecked")
      EdgeArticulationFunctionSupplier<BasicBlockEdge> supplier =
          (EdgeArticulationFunctionSupplier<BasicBlockEdge>) layout;
      return supplier.getEdgeArticulationFunction();
    }

    return DUMMY_ARTICULATOR;
  }

  private AnvillTempGraph buildGraph(VisualGraph<BasicBlockVertex, BasicBlockEdge> visualGraph) {

    AnvillTempGraph tempGraph = new AnvillTempGraph();

    Collection<BasicBlockVertex> vertices = visualGraph.getVertices();
    for (BasicBlockVertex v : vertices) {
      tempGraph.addVertex(v);
    }

    Collection<BasicBlockEdge> edges = visualGraph.getEdges();
    for (BasicBlockEdge e : edges) {
      tempGraph.addEdge(e.getStart(), e.getEnd(), e);
    }

    return tempGraph;
  }

  private Predicate<BasicBlockEdge> getFavoredEdgePredicate() {
    return e -> e.getFlowType().equals(RefType.FALL_THROUGH);
  }

  private class AnvillTempGraph extends AbstractBaseGraph<BasicBlockVertex, BasicBlockEdge> {

    protected AnvillTempGraph() {
      super(null, null, DefaultGraphType.directedPseudograph());
    }

  }

  private class BasicBlockEdgeComparator implements Comparator<BasicBlockEdge> {

    // TODO we can update the edge priority used when layout out the graph, which is what the
    // generic graphing does.   In order to change edge priorities, we would have to verify
    // the effects on the layout are desirable for the Function Graph.
    // private Map<String, Integer> edgePriorityMap = new HashMap<>();

    public BasicBlockEdgeComparator() {

			/*

			 // populate map with RefType values; defined in priority order

			 int priority = 0;
			 edgePriorityMap.put("Fall-Through", priority++);
			 edgePriorityMap.put("Conditional-Return", priority++);
			 edgePriorityMap.put("Unconditional-Jump", priority++);
			 edgePriorityMap.put("Conditional-Jump", priority++);
			 edgePriorityMap.put("Unconditional-Call", priority++);
			 edgePriorityMap.put("Conditional-Call", priority++);
			 edgePriorityMap.put("Terminator", priority++);
			 edgePriorityMap.put("Computed", priority++);
			 edgePriorityMap.put("Indirection", priority++);
			 edgePriorityMap.put("Entry", priority++);

			 */
    }

    @Override
    public int compare(BasicBlockEdge e1, BasicBlockEdge e2) {
      return priority(e1).compareTo(priority(e2));
    }

    private Integer priority(BasicBlockEdge e) {
      FlowType type = e.getFlowType();
      if (type == RefType.FALL_THROUGH) {
        return 1;  // lower is more preferred
      }
      return 10;
    }
  }
}
