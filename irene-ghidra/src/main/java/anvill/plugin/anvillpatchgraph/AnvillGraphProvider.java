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
package anvill.plugin.anvillpatchgraph;

import static anvill.plugin.anvillpatchgraph.graph.AnvillVertex.LOCK_IMAGE;
import static anvill.plugin.anvillpatchgraph.graph.AnvillVertex.UNLOCK_IMAGE;

import anvill.PatchLangGrpcClient;
import anvill.ProgramSpecifier;
import anvill.RequiredSymbolsManager;
import anvill.SplitsManager;
import anvill.decompiler.DecompilerServerException;
import anvill.decompiler.DecompilerServerManager;
import anvill.decompiler.DockerDecompilerServerManager;
import anvill.plugin.anvillpatchgraph.AnvillPatchInfo.Patch;
import anvill.plugin.anvillpatchgraph.action.*;
import anvill.plugin.anvillpatchgraph.graph.*;
import anvill.plugin.anvillpatchgraph.graph.jung.renderer.AnvillEdgePaintTransformer;
import anvill.plugin.anvillpatchgraph.layout.AnvillGraphLayoutProvider;
import anvill.plugin.anvillpatchgraph.layout.BBGraphLayout;
import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.EventTrigger;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import edu.uci.ics.jung.visualization.RenderContext;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.nav.DecoratorPanel;
import ghidra.app.services.GoToService;
import ghidra.app.util.PluginConstants;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.preferences.Preferences;
import ghidra.graph.VisualGraphComponentProvider;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.actions.VisualGraphContextMarker;
import ghidra.graph.viewer.event.mouse.VertexMouseInfo;
import ghidra.graph.viewer.renderer.VisualGraphEdgeLabelRenderer;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.filechooser.GhidraFileFilter;
import ghidra.util.task.*;
import io.grpc.*;
import io.grpc.Status.Code;
import irene3.server.PatchService;
import irene3.server.PatchService.PatchGraph;
import java.awt.Color;
import java.awt.event.MouseEvent;
import java.io.*;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.TimeUnit;
import javax.swing.*;
import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.DualHashBidiMap;
import resources.Icons;
import resources.ResourceManager;
import specification.specification.Specification;

public class AnvillGraphProvider
    extends VisualGraphComponentProvider<BasicBlockVertex, BasicBlockEdge, BasicBlockGraph> {

  public static final String LAST_IMPORTFILE_PREFERENCE_KEY = "AnvillGraphProvider.ImportFile";
  public static final String RELAYOUT_GRAPH_ACTION_NAME = "Relayout Graph";
  public static final String LOAD_PATCHES_ACTION_NAME = "Load Patch File";
  public static final String SAVE_PATCHES_ACTION_NAME = "Save Patches";
  public static final String DECOMPILE_ACTION_NAME = "Decompile and Patch Function";
  public static final String ADD_REFERENCE_TO_GLOBAL = "Add reference to global";
  public static final ImageIcon REFERENCES_TO_ICON;
  private final GhidraFileFilter JSON_FILE_FILTER =
      ExtensionFileFilter.forExtensions("JSON files", "json");

  private final GhidraFileFilter C_FILE_FILTER = ExtensionFileFilter.forExtensions("C files", "c");

  static {
    REFERENCES_TO_ICON = ResourceManager.loadImage("images/references_to.gif");
  }

  private final PluginTool tool;
  private final AnvillPatchGraphPlugin plugin;
  private DecoratorPanel decorationPanel;
  private Program currentProgram;
  private BasicBlockGraph graph;
  private ProgramLocation currentLocation;
  private VisualGraphView<BasicBlockVertex, BasicBlockEdge, BasicBlockGraph> view;
  private AnvillGraphLayoutProvider layoutProvider;
  private boolean isConnected;
  private GhidraFileChooser loadFileChooser;
  private GhidraFileChooser saveFileChooser;
  private anvill.plugin.anvillpatchgraph.AnvillPatchInfo anvillPatchInfo;
  private ArrayList<Symbol> anvillRequiredGlobals = new ArrayList<>();
  private ProgramLocation pendingLocation;
  private SwingUpdateManager updateLocationUpdateManager;
  private ManagedChannel grpcChannel;
  private PatchLangGrpcClient grpcClient;

  private final DecompilerServerManager decompilerServerManager =
      new DockerDecompilerServerManager(50080);

  public AnvillGraphProvider(AnvillPatchGraphPlugin anvillPatchGraphPlugin, boolean isConnected) {
    super(
        anvillPatchGraphPlugin.getTool(),
        AnvillPatchGraphPlugin.GRAPH_NAME,
        anvillPatchGraphPlugin.getName());
    this.tool = anvillPatchGraphPlugin.getTool();
    this.plugin = anvillPatchGraphPlugin;

    // View is handled by FGController in upstream
    view = new VisualGraphView<>();
    // these default to off; they are typically controlled via a UI element; the
    // values set here are arbitrary and are for demo purposes
    view.setVertexFocusPathHighlightMode(PathHighlightMode.OUT);
    view.setVertexHoverPathHighlightMode(PathHighlightMode.IN);
    view.setVertexFocusListener(
        v -> {
          ProgramLocation location = new ProgramLocation(getProgram(), v.getVertexAddress());
          this.goTo(location);
        });

    setConnected(isConnected);
    setIcon(AnvillPatchGraphPlugin.ICON);

    if (!isConnected) {
      setTransient();
    } else {
      addToToolbar();
    }

    decorationPanel = new DecoratorPanel(view.getViewComponent(), isConnected);
    setWindowMenuGroup(AnvillPatchGraphPlugin.GRAPH_NAME);
    setWindowGroup(AnvillPatchGraphPlugin.GRAPH_NAME);
    setDefaultWindowPosition(WindowPosition.WINDOW);

    setHelpLocation(AnvillPatchGraphPlugin.DEFAULT_HELP);

    addToTool();
    addSatelliteFeature();

    createActions();

    updateLocationUpdateManager =
        new SwingUpdateManager(250, 750, () -> setPendingLocationFromUpdateManager());
  }

  private BBGraphOptions getAnvillGraphOptions() {
    return plugin.getGraphOptions();
  }

  @Override
  public boolean isSnapshot() {
    // we are a snapshot when we are 'disconnected'
    return !isConnected();
  }

  public boolean isConnected() {
    return isConnected;
  }

  public void setConnected(boolean newValue) {
    isConnected = newValue;
  }

  /** Install/build the graph, rebuilding when necessary */
  private void installGraph() {
    installGraph(false);
  }

  /**
   * Install/build the graph with the option to force a rebuild even if in the same function
   *
   * @param forceRebuild Whether to always rebuild
   */
  private void installGraph(boolean forceRebuild) {
    if (currentProgram == null || currentLocation == null || anvillPatchInfo == null) {
      return;
    }

    if (graph != null) {
      // Don't rebuild if we already have a graph of the location
      if (!forceRebuild && graph.getFunction().getBody().contains(currentLocation.getAddress())) {
        Msg.info(this, "Not rebuilding graph because already in function");
        return;
      }
      graph.dispose();
    }

    try {
      buildGraph();
    } catch (CancelledException e) {
      Msg.info(getClass(), "Canceled building Anvill graph");
    }

    if (graph == null) {
      Msg.info(this, "Couldn't build the graph due to other reasons like no patch data");
      return;
    }

    view.setLayoutProvider(layoutProvider);
    view.setGraph(graph);

    // TODO: This appears in FGComponent.java in 'createPrimaryGraphViewer'
    RenderContext<BasicBlockVertex, BasicBlockEdge> renderContext =
        view.getPrimaryGraphViewer().getRenderContext();
    AnvillEdgePaintTransformer edgePaintTransformer =
        new AnvillEdgePaintTransformer(getAnvillGraphOptions());
    renderContext.setEdgeDrawPaintTransformer(edgePaintTransformer);
    renderContext.setArrowDrawPaintTransformer(edgePaintTransformer);
    renderContext.setArrowFillPaintTransformer(edgePaintTransformer);

    // note: disable focus keys here to avoid tab getting consumed
    view.getPrimaryGraphViewer().setFocusTraversalKeysEnabled(false);

    // edge label rendering
    com.google.common.base.Function<BasicBlockEdge, String> edgeLabelTransformer =
        BasicBlockEdge::getLabel;
    renderContext.setEdgeLabelTransformer(edgeLabelTransformer);

    // note: this label renderer is the stamp for the label; we use another edge
    // label
    // renderer inside of the VisualGraphRenderer
    VisualGraphEdgeLabelRenderer edgeLabelRenderer = new VisualGraphEdgeLabelRenderer(Color.BLACK);
    edgeLabelRenderer.setNonPickedForegroundColor(Color.LIGHT_GRAY);
    edgeLabelRenderer.setRotateEdgeLabels(false);
    renderContext.setEdgeLabelRenderer(edgeLabelRenderer);
  }

  public void setProgram(Program newProgram) {
    currentProgram = newProgram;
  }

  public void goTo(ProgramLocation newLocation) {
    if (graph != null
        && graph
            .getVertexAtAddr(currentLocation.getAddress())
            .equals(graph.getVertexAtAddr(newLocation.getAddress()))) {
      // Already at a location in this vertex. Don't do anything else
      return;
    }
    GoToService goToService = tool.getService(GoToService.class);
    goToService.goTo(newLocation);
  }

  /**
   * Called when for location changes that are <b>external</b> to the function graph (e.g., when the
   * user clicks in Ghidra's Listing window)
   *
   * @param newLocation the new location
   */
  public void setLocation(ProgramLocation newLocation) {
    pendingLocation = newLocation;
    updateLocationUpdateManager.update();
  }

  private void setPendingLocationFromUpdateManager() {
    if (pendingLocation == null) {
      return;
    }

    ProgramLocation newLocation = pendingLocation;
    pendingLocation = null;
    if (SystemUtilities.isEqual(currentLocation, newLocation)) {
      return;
    }

    setLocationNow(newLocation);
  }

  private void setLocationNow(ProgramLocation newLocation) {
    if (newLocation == null) {
      return;
    }

    if (SystemUtilities.isEqual(currentLocation, newLocation)) {
      return;
    }

    storeLocation(newLocation);
    displayLocation(newLocation);
    notifyContextChanged();
  }

  void displayLocation(ProgramLocation newLocation) {
    Address newAddress = newLocation != null ? newLocation.getAddress() : null;
    if (isVisible() && newAddress != null) {
      // Select a new vertex and center it
      if (graph != null && graph.getFunction().getBody().contains(newAddress)) {
        BasicBlockVertex newVertex = graph.getVertexAtAddr(newAddress);
        if (newVertex != null) {
          // This only centers the title-bar
          view.getViewUpdater().ensureVertexVisible(newVertex, null);
          view.getGraphComponent().setVertexFocused(newVertex);
          view.repaint();
        } else {
          Msg.info(this, "Weird: No vertex for graph");
        }
      } else {
        // New addr not in function or user needs to import new patches
        installGraph();
      }
    }
  }

  private void storeLocation(ProgramLocation location) {
    currentLocation = location;
  }

  private void buildGraph() throws CancelledException {
    Function function =
        currentProgram.getFunctionManager().getFunctionContaining(currentLocation.getAddress());
    if (function == null) {
      Msg.info(getClass(), "No function at current location: " + currentLocation);
      graph = null;
      return;
    }

    AddressSetView addresses = function.getBody();
    TaskMonitor monitor = new DummyCancellableTaskMonitor();
    CodeBlockModel blockModel = new BasicBlockModel(currentProgram);

    // Prepare our patch info mappings
    Map<CodeBlock, List<Patch>> blkToPatches = new HashMap<>();
    for (Patch patch : anvillPatchInfo.getPatches()) {
      Address patchAddr = currentProgram.getAddressFactory().getAddress(patch.getAddress());
      if (!addresses.contains((patchAddr))) {
        // If the patch file contains blocks from another function, don't graph these.
        continue;
      }

      CodeBlock[] blks = blockModel.getCodeBlocksContaining(patchAddr, monitor);
      if (blks.length == 0) {
        Msg.info(this, "No block found for patch addr: " + patchAddr.toString());
        graph = null;
        return;
      } else if (blks.length > 1) {
        Msg.info(this, "Multiple blocks found for patch addr: " + patchAddr.toString());
        graph = null;
        return;
      }

      CodeBlock blk = blks[0];
      if (!blkToPatches.containsKey(blk)) {
        blkToPatches.put(blk, new ArrayList<>());
      }
      List<Patch> blkPatches = blkToPatches.get(blk);
      blkPatches.add(patch);
    }
    graph = new BasicBlockGraph(function);

    // TODO: See FunctionGraphFactory for more complete details
    // **** Vertices
    BidiMap<CodeBlock, List<BasicBlockVertex>> vertices = new DualHashBidiMap<>();

    CodeBlockIterator iterator = blockModel.getCodeBlocksContaining(addresses, monitor);
    monitor.initialize(addresses.getNumAddresses());

    while (iterator.hasNext()) {
      CodeBlock codeBlock = iterator.next();
      List<Patch> blkPatches = blkToPatches.get(codeBlock);
      if (blkPatches == null || blkPatches.isEmpty()) {
        Msg.info(
            this,
            "This function contains a basic block address that has no corresponding patch: "
                + codeBlock.getMinAddress());
        graph = null;
        return;
      }

      List<BasicBlockVertex> blockVertices = new ArrayList<>();
      for (Patch patch : blkPatches) {
        blockVertices.add(new AnvillVertex(codeBlock, patch, grpcClient));
      }
      // Make sure that blocks that correspond to the same Ghidra code block
      // are in chronological order. For zero-byte block insertion, the
      // zero-byte block is always first
      blockVertices.sort(Comparator.comparing(BasicBlockVertex::getSize));
      blockVertices.sort(Comparator.comparing(BasicBlockVertex::getVertexAddress));
      vertices.put(codeBlock, blockVertices);

      long blockAddressCount = codeBlock.getNumAddresses();
      long currentProgress = monitor.getProgress();
      monitor.setProgress(currentProgress + blockAddressCount);
    }

    // **** Edges
    Collection<BasicBlockEdge> edges = new ArrayList<>();
    for (List<BasicBlockVertex> startVertices : vertices.values()) {
      if (startVertices.size() > 1) {
        // If we have a prologue and/or epilogue, it's possible to have multiple
        // vertices for the same Ghidra code block.
        // These will all map to the same Ghidra code block, however we know
        // that the flow type should be "fall-through".
        for (int i = 0; i < startVertices.size() - 1; ++i) {
          BasicBlockVertex startVertex = startVertices.get(i);
          BasicBlockVertex destinationVertex = startVertices.get(i + 1);
          edges.add(new AnvillEdge(startVertex, destinationVertex, FlowType.FALL_THROUGH));
        }
      }
      // Flows should all start from the last vertex for a given code block.
      BasicBlockVertex startVertex = startVertices.get(startVertices.size() - 1);
      CodeBlock codeBlock = vertices.getKey(startVertices);
      CodeBlockReferenceIterator destinations = codeBlock.getDestinations(monitor);
      while (destinations.hasNext()) {
        CodeBlockReference reference = destinations.next();
        CodeBlock destinationBlock = reference.getDestinationBlock();
        List<BasicBlockVertex> destinationVertices = vertices.get(destinationBlock);
        if (destinationVertices == null) {
          continue; // no vertex means the code block is not in our function
        }

        // If a destination has more than one vertex, we should choose the first one.
        // For example,
        // if a block has a flow
        // to a terminating block, the edge should point at the block just before the
        // epilogue block
        // rather than the
        // epilogue block itself.
        BasicBlockVertex destinationVertex = destinationVertices.get(0);
        edges.add(new AnvillEdge(startVertex, destinationVertex, reference.getFlowType()));
      }
    }

    // **** Graph
    vertices.values().forEach(vtxs -> vtxs.forEach(v -> graph.addVertex(v)));
    edges.forEach(e -> graph.addEdge(e));

    graph.setOptions(plugin.getGraphOptions());

    // **** Layout
    try {
      BBGraphLayout layout = layoutProvider.getLayout(graph, TaskMonitor.DUMMY);
      graph.setLayout(layout);
    } catch (CancelledException e) {
      // can't happen as long as we're using the dummy monitor
    }
  }

  public BasicBlockGraph getGraph() {
    return graph;
  }

  public VisualGraphViewUpdater<BasicBlockVertex, BasicBlockEdge> getGraphViewUpdater() {
    GraphViewer<BasicBlockVertex, BasicBlockEdge> viewer = view.getPrimaryGraphViewer();
    return viewer.getViewUpdater();
  }

  @Override
  public void dispose() {
    grpcClient = null;
    if (grpcChannel != null) {
      try {
        grpcChannel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
      } catch (InterruptedException e) {
        throw new RuntimeException(e);
      }
    }
    decompilerServerManager.dispose();
    super.dispose();
    removeFromTool();
  }

  @Override
  public VisualGraphView<BasicBlockVertex, BasicBlockEdge, BasicBlockGraph> getView() {
    return view;
  }

  @SuppressWarnings("unchecked")
  @Override
  public ActionContext getActionContext(MouseEvent event) {
    if (currentProgram == null || currentLocation == null) {
      return null;
    }

    if (currentProgram.getFunctionManager().getFunctionContaining(currentLocation.getAddress())
        == null) {
      return new AnvillGraphEmptyGraphActionContext(this);
    }

    if (event == null) { // keybinding/menu/toolbar (no popup)
      return createKeybindingContext();
    }

    Object source = event.getSource();
    if (source instanceof SatelliteGraphViewer) {
      // we may want to change the actions over the satellite in the future
      return new AnvillGraphSatelliteViewerActionContext(this);
    } else if (source instanceof VisualGraphContextMarker) {
      return new AnvillGraphValidGraphActionContext(this, new HashSet<BasicBlockVertex>());
    }

    if (source instanceof GraphViewer) {
      GraphViewer<BasicBlockVertex, BasicBlockEdge> viewer =
          (GraphViewer<BasicBlockVertex, BasicBlockEdge>) source;

      Set<BasicBlockVertex> selectedVertices = getSelectedVertices();
      VertexMouseInfo<BasicBlockVertex, BasicBlockEdge> vertexMouseInfo =
          GraphViewerUtils.convertMouseEventToVertexMouseEvent(viewer, event);
      if (vertexMouseInfo == null) {
        return new AnvillGraphValidGraphActionContext(this, selectedVertices);
      }

      BasicBlockVertex vertexAtPoint = vertexMouseInfo.getVertex();
      VertexActionContextInfo vertexInfo = createContextInfo(vertexAtPoint);
      if (view.isScaledPastInteractionThreshold() || vertexMouseInfo.isGrabArea()) {
        return new AnvillGraphUneditableVertexLocationActionContext(this, vertexInfo);
      }

      if (selectedVertices.size() > 1) {
        return new AnvillGraphUneditableVertexLocationActionContext(this, vertexInfo);
      }

      return new AnvillGraphEditableVertexLocationActionContext(this, vertexInfo);
    }

    throw new AssertException(
        "Received mouse event from unexpected source in getActionContext(): " + source);
  }

  private ActionContext createKeybindingContext() {
    boolean isPastInteractionThreshold = view.isScaledPastInteractionThreshold();
    BasicBlockVertex vertex = view.getFocusedVertex();
    if (vertex == null || isPastInteractionThreshold) {
      return new AnvillGraphValidGraphActionContext(this, getSelectedVertices());
    }

    VertexActionContextInfo vertexInfo = createContextInfo(vertex);
    return new AnvillGraphEditableVertexLocationActionContext(this, vertexInfo);
  }

  private VertexActionContextInfo createContextInfo(BasicBlockVertex vertex) {
    AddressSet hoveredVerticesAddresses = getAddressesFromHoveredVertices();
    AddressSet selectedVerticesAddresses = getAddressesForSelectedVertices();
    Set<BasicBlockVertex> selectedVertices = getSelectedVertices();
    return new VertexActionContextInfo(
        vertex, selectedVertices, hoveredVerticesAddresses, selectedVerticesAddresses);
  }

  AddressSet getAddressesFromHoveredVertices() {
    AddressSet addresses = new AddressSet();
    if (currentProgram == null || graph == null) {
      return addresses;
    }

    Collection<BasicBlockVertex> hoveredVertices =
        GraphViewerUtils.getVerticesOfHoveredEdges(graph);
    for (BasicBlockVertex vertex : hoveredVertices) {
      addresses.add(vertex.getAddresses());
    }
    return addresses;
  }

  private AddressSet getAddressesForSelectedVertices() {
    AddressSet addresses = new AddressSet();
    if (currentProgram == null || graph == null) {
      return addresses;
    }

    Collection<BasicBlockVertex> selectedVertices =
        GraphViewerUtils.getVerticesOfSelectedEdges(graph);
    for (BasicBlockVertex vertex : selectedVertices) {
      addresses.add(vertex.getAddresses());
    }
    return addresses;
  }

  @Override
  public void componentShown() {
    super.componentShown();

    installGraph(true);

    displayLocation(currentLocation);
    notifyContextChanged();
  }

  @Override
  public void closeComponent() {
    view.cleanup();
    plugin.closeProvider(this);
  }

  @Override
  public JComponent getComponent() {
    return decorationPanel;
  }

  public static void addSliceToSaveList(ActionContext actionContext) {
    if (actionContext instanceof ProgramLocationActionContext context) {
      if (!context.hasSelection()) {
        return;
      }
      var highlight = context.getSelection();
      var minSplit = highlight.getMinAddress();

      var listing = context.getProgram().getListing();

      // The selection's max address gives us the address of the last highlighted instruction,
      // whereas we want the address of the instruction after.
      var currInst = listing.getInstructionContaining(highlight.getMaxAddress());

      var maxSplit = highlight.getMaxAddress();
      if (currInst != null) {
        maxSplit = currInst.getMaxAddress().add(1);
      }

      var func = listing.getFunctionContaining(minSplit);
      if (func == null || func != listing.getFunctionContaining(highlight.getMaxAddress())) {
        return;
      }

      var splits = new SplitsManager(context.getProgram());

      splits.addSplitForAddress(func.getEntryPoint(), minSplit);
      splits.addSplitForAddress(func.getEntryPoint(), maxSplit);

      Msg.debug(
          AnvillGraphProvider.class,
          "Added selection between "
              + minSplit.toString()
              + " and "
              + maxSplit.toString()
              + " for "
              + func.getName());
    }
  }

  public static class AddToPatchSliceAction
      extends anvill.plugin.anvillpatchgraph.AnvillGraphAction {

    public AddToPatchSliceAction(AnvillPatchGraphPlugin plugin) {
      super(plugin, "Add Patch To Slice");
      setPopupMenuData(new MenuData(new String[] {"Add selection to slice"}, "New"));
      setDescription("Adds selection to the working patch slice for this function");
    }

    @Override
    public void runInAction(TaskMonitor monitor, ActionContext actionContext) {
      addSliceToSaveList(actionContext);
    }
  }

  public enum AddZeroByteBlockDirection {
    AFTER,
    BEFORE
  }

  public void addZeroByteBlock(ActionContext actionContext, AddZeroByteBlockDirection direction) {
    if (actionContext instanceof ProgramLocationActionContext context) {
      var listing = this.getProgram().getListing();
      Address addr;
      // Check direction of insertion
      switch (direction) {
        case BEFORE -> {
          addr = context.getSelection().getMinAddress();
          if (addr == null) {
            addr = context.getAddress();
          }
          var insn = listing.getInstructionAt(addr);
          if (insn == null || listing.getFunctionContaining(insn.getAddress()) == null) {
            Msg.showError(
                this,
                null,
                "Address outside function",
                "Cannot add zero byte block outside of function body");
            return;
          }
          addr = insn.getAddress();
        }
        case AFTER -> {
          addr = context.getSelection().getMaxAddress();
          if (addr == null) {
            addr = context.getAddress();
          }
          var afterInsn = listing.getInstructionAfter(addr);
          if (afterInsn == null || listing.getFunctionContaining(afterInsn.getAddress()) == null) {
            Msg.showError(
                this,
                null,
                "Address outside function",
                "Cannot add zero byte block outside of function body");
            return;
          }
          addr = afterInsn.getAddress();
        }
        default -> {
          Msg.info(this, "Bad direction for adding zero-byte block: " + direction);
          return;
        }
      }

      new SplitsManager(this.currentProgram)
          .insertZeroByteBlock(listing.getFunctionContaining(addr).getEntryPoint(), addr);
    } else {
      Msg.info(
          AnvillGraphProvider.class,
          "Unknown action context for `addZeroByteBlock` action: " + actionContext);
    }
  }

  public static class AddBlockBeforeAction
      extends anvill.plugin.anvillpatchgraph.AnvillGraphAction {
    private final AnvillGraphProvider provider;

    public AddBlockBeforeAction(AnvillPatchGraphPlugin plugin, AnvillGraphProvider provider) {
      super(plugin, "Add Patch Block Before");
      var m = new MenuData(new String[] {"Add patch block before instruction(s)"}, "New");
      m.setMenuSubGroup("1");
      setPopupMenuData(m);
      setDescription("Adds a zero-byte patch block before the currently selected instruction(s).");
      this.provider = provider;
    }

    @Override
    public void runInAction(TaskMonitor monitor, ActionContext actionContext) {
      Swing.runIfSwingOrRunLater(
          () -> provider.addZeroByteBlock(actionContext, AddZeroByteBlockDirection.BEFORE));
    }
  }

  public static class AddBlockAfterAction extends anvill.plugin.anvillpatchgraph.AnvillGraphAction {
    private final AnvillGraphProvider provider;

    public AddBlockAfterAction(AnvillPatchGraphPlugin plugin, AnvillGraphProvider provider) {
      super(plugin, "Add Patch Block After");
      var m = new MenuData(new String[] {"Add patch block after instruction(s)"}, "New");
      m.setMenuSubGroup("2");
      setPopupMenuData(m);
      setDescription("Adds a zero-byte patch block after the currently selected instruction(s).");
      this.provider = provider;
    }

    @Override
    public void runInAction(TaskMonitor monitor, ActionContext actionContext) {
      provider.addZeroByteBlock(actionContext, AddZeroByteBlockDirection.AFTER);
    }
  }

  private void createActions() {
    DockingAction loadPatches =
        new anvill.plugin.anvillpatchgraph.AnvillGraphAction(
            this.plugin, LOAD_PATCHES_ACTION_NAME) {
          @Override
          public void runInAction(TaskMonitor monitor, ActionContext actionContext) {
            importPatchesAction();
          }

          @Override
          public void onTaskCompleted() {
            installGraph(true);
            displayLocation(currentLocation);
            notifyContextChanged();
          }
        };
    loadPatches.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
    loadPatches.setEnabled(true);
    loadPatches.markHelpUnnecessary();
    addLocalAction(loadPatches);

    DockingAction decompileAction =
        new anvill.plugin.anvillpatchgraph.AnvillGraphAction(this.plugin, DECOMPILE_ACTION_NAME) {
          @Override
          public void runInAction(TaskMonitor monitor, ActionContext actionContext) {
            decompileFunction();
          }

          @Override
          public void onTaskCompleted() {
            installGraph(true);
            displayLocation(currentLocation);
            notifyContextChanged();
          }
        };
    decompileAction.setToolBarData(
        new ToolBarData(ResourceManager.loadImage("images/Browser.gif"), null));
    // TODO: Only enable if on a function
    decompileAction.setEnabled(true);
    decompileAction.markHelpUnnecessary();
    addLocalAction(decompileAction);

    var sliceActionDecomp = new AddToPatchSliceAction(this.plugin);
    var sliceActionCode = new AddToPatchSliceAction(this.plugin);
    this.tool.addLocalAction(this.tool.getComponentProvider("Decompiler"), sliceActionDecomp);
    this.tool.addLocalAction(
        this.tool.getComponentProvider(PluginConstants.CODE_BROWSER), sliceActionCode);

    // TODO(alex): Only enable the action when there's a selection.
    sliceActionDecomp.setEnabled(true);
    sliceActionCode.setEnabled(true);

    var addBlockBeforeActionDecomp = new AddBlockBeforeAction(plugin, this);
    var addBlockBeforeActionCode = new AddBlockBeforeAction(plugin, this);
    var addBlockAfterActionDecomp = new AddBlockAfterAction(plugin, this);
    var addBlockAfterActionCode = new AddBlockAfterAction(plugin, this);
    tool.addLocalAction(tool.getComponentProvider("Decompiler"), addBlockBeforeActionDecomp);
    tool.addLocalAction(
        tool.getComponentProvider(PluginConstants.CODE_BROWSER), addBlockBeforeActionCode);
    tool.addLocalAction(tool.getComponentProvider("Decompiler"), addBlockAfterActionDecomp);
    tool.addLocalAction(
        tool.getComponentProvider(PluginConstants.CODE_BROWSER), addBlockAfterActionCode);
    addBlockBeforeActionDecomp.setEnabled(true);
    addBlockBeforeActionCode.setEnabled(true);
    addBlockAfterActionDecomp.setEnabled(true);
    addBlockAfterActionCode.setEnabled(true);

    DockingAction lockAction =
        new DockingAction("Lock Menu", plugin.getName()) {
          @Override
          public void actionPerformed(ActionContext context) {
            AnvillGraphValidGraphActionContextIf graphContext =
                (AnvillGraphValidGraphActionContextIf) context;
            // Guaranteed to be 1 and an AnvillVertex
            var vertex = (AnvillVertex) graphContext.getSelectedVertices().iterator().next();
            vertex.edit_toggle();
          }

          @Override
          public boolean isEnabledForContext(ActionContext context) {
            if (!(context instanceof AnvillGraphValidGraphActionContextIf)) {
              return false;
            }
            Set<BasicBlockVertex> vertices =
                ((AnvillGraphValidGraphActionContextIf) context).getSelectedVertices();
            if (vertices.size() != 1) {
              return false;
            }
            BasicBlockVertex vertex = vertices.iterator().next();
            MenuData menu = getPopupMenuData();
            menu.setIcon(vertex.isEditable() ? LOCK_IMAGE : UNLOCK_IMAGE);
            menu.setMenuPath(
                new String[] {vertex.isEditable() ? "Lock Editing" : "Unlock Editing"});
            return true;
          }

          @Override
          public boolean isAddToPopup(ActionContext context) {
            if (!(context instanceof AnvillGraphValidGraphActionContextIf)) {
              return false;
            }
            return true;
          }
        };
    MenuData menuData = new MenuData(new String[] {"Toggle Editing Popup"});
    lockAction.setPopupMenuData(menuData);
    addLocalAction(lockAction);

    addLayoutAction();
  }

  private void decompileFunction() {
    setupGrpcClient();

    Function func =
        currentProgram.getFunctionManager().getFunctionContaining(currentLocation.getAddress());
    if (func == null) {
      Msg.showWarn(
          this, null, "No function", "IRENE cannot decompile null function at " + currentLocation);
      return;
    }
    var id = currentProgram.startTransaction("Generating anvill patch");
    Specification spec;
    try {
      var split_man = new SplitsManager(currentProgram);
      var funcSplitAddrs = split_man.getSplitsForAddressJava(func.getEntryPoint());
      var zeroByteAddrs = split_man.getZeroBlocksForAddressJava(func.getEntryPoint());

      var sym_set = new scala.collection.immutable.HashSet<Symbol>();
      // TODO(frabert): This is pretty bad... but also I don't expect
      // tons of required globals
      var sym_man = new RequiredSymbolsManager(this.currentProgram);
      for (var sym : sym_man.getRequiredSymbols(func.getEntryPoint())) {
        var reqsym = this.currentProgram.getSymbolTable().getSymbols(sym);
        while (reqsym.hasNext()) {
          sym_set = (scala.collection.immutable.HashSet<Symbol>) sym_set.$plus(reqsym.next());
        }
      }
      spec =
          ProgramSpecifier.specifySingleFunctionWithSplits(
              func, funcSplitAddrs, sym_set, zeroByteAddrs);
    } finally {
      currentProgram.endTransaction(id, true);
    }
    if (spec == null) {
      Msg.showWarn(
          this,
          null,
          "Cannot create specification",
          "IRENE cannot create a specification for function " + func);
      return;
    }

    boolean connected = false;
    int retry = 0;
    Optional<PatchGraph> maybeCodegen = Optional.empty();
    while (!connected && retry < 10) {
      // NOTE: There isn't an easy way to check whether the gRPC server is actually
      // available unless you try an RPC, so we have this logic to first attempt
      // the RPC and if it fails, attempt to automatically start it.
      try {
        maybeCodegen = grpcClient.processSpec(Specification.toJavaProto(spec));
        connected = true;
      } catch (StatusRuntimeException statusRuntimeException) {
        if (Code.UNAVAILABLE.equals(statusRuntimeException.getStatus().getCode())) {
          try {
            decompilerServerManager.startPatchLangServer();
          } catch (DecompilerServerException e) {
            Msg.showError(
                this,
                view.getPrimaryGraphViewer(),
                "Cannot Automatically Start PatchLang Server",
                e.getMessage(),
                e.getCause());
            break;
          }
          retry++;
          // Sleep for a bit to let things boot.
          try {
            Thread.sleep(500);
          } catch (InterruptedException interruptedException) {
            // Don't care
          }
        } else {
          // Some other issue
          connected = true;
          Msg.showError(
              this,
              view.getPrimaryGraphViewer(),
              "Issue With PatchLang Server",
              "Issue: " + statusRuntimeException.getMessage(),
              statusRuntimeException);
        }
      }
    }
    if (!connected)
      Msg.showError(
          this,
          view.getPrimaryGraphViewer(),
          "Could Not Connect To PatchLang Server",
          "Could not start or connect to PatchLang server even though we tried starting it");

    if (maybeCodegen.isPresent()) {
      try {
        anvillPatchInfo = new anvill.plugin.anvillpatchgraph.AnvillPatchInfo(maybeCodegen.get());
      } catch (InstantiationException e) {
        Msg.showError(this, null, "Bad patch", "Could not import patch: " + e.getMessage());
        anvillPatchInfo = null;
      }
      Msg.debug(this, maybeCodegen.get().toString());
    } else {
      anvillPatchInfo = null;
    }
  }

  private void setupGrpcClient() {
    if (grpcChannel == null) {
      try {
        grpcChannel =
            Grpc.newChannelBuilder("localhost:50080", InsecureChannelCredentials.create()).build();
      } catch (NoSuchMethodError e) {
        // NOTE(ekilmer): We need this to gracefully handle the error and report it to
        // the user.
        // Ghidra 10.3 should fix this when it's released.
        if (e.getMessage().contains("com.google.common.base.Preconditions.checkArgument")) {
          Msg.showError(
              this,
              null,
              "Must patch Ghidra",
              "Please patch Ghidra with a new version of Guava in 'Ghidra/Framework/Generic/lib'",
              e);
        }
      }
    }
    if (grpcClient == null) {
      grpcClient = new PatchLangGrpcClient(grpcChannel);
    }
  }

  /** Update patch models with potentially user-changed text in the graph vertices. */
  public void updatePatchModel() {
    if (graph == null || anvillPatchInfo == null) {
      return;
    }
    for (BasicBlockVertex v : graph.getVertices()) {
      // We know our graph is full of Anvill vertices
      AnvillVertex av = (AnvillVertex) v;
      Patch patch = av.getPatch();
      patch.setCode(av.getText());
    }
  }

  private void importPatchesAction() {
    initializeLoadFileChooser();
    File file = loadFileChooser.getSelectedFile();
    if (loadFileChooser.wasCancelled()) {
      return;
    }
    if (file == null) {
      Msg.showInfo(this, tool.getActiveWindow(), "No file selected", "No file will be imported");
    } else if (!file.exists()) {
      Msg.showInfo(
          this,
          tool.getActiveWindow(),
          "File does not exist.",
          "File does not exist: " + file.getAbsolutePath());
    } else {
      importPatchesFile(file);
    }
  }

  void importPatchesFile(File file) {
    anvillPatchInfo = null;
    PatchGraph patchGraph;
    try {
      patchGraph = PatchService.PatchGraph.parseFrom(Files.readAllBytes(file.toPath()));
      anvillPatchInfo = new AnvillPatchInfo(patchGraph);
    } catch (InstantiationException | IOException e) {
      Msg.showError(
          this,
          tool.getActiveWindow(),
          "Bad PatchLang file",
          "Could not import PatchLang patch: " + e.getMessage());
      anvillPatchInfo = null;
      return;
    }
    Preferences.setProperty(LAST_IMPORTFILE_PREFERENCE_KEY, file.getAbsolutePath());
    Preferences.store();
  }

  void importPatchesFileSynchronous(File file) {
    this.importPatchesFile(file);
    installGraph(true);
    displayLocation(currentLocation);
    notifyContextChanged();
  }

  private void initializeLoadFileChooser() {
    if (loadFileChooser == null) {
      loadFileChooser = new GhidraFileChooser(tool.getActiveWindow());
      loadFileChooser.addFileFilter(JSON_FILE_FILTER);
      loadFileChooser.setSelectedFileFilter(JSON_FILE_FILTER);
    }
    loadFileChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
    loadFileChooser.setMultiSelectionEnabled(false);
    loadFileChooser.setTitle("Choose Patch File To Import");
    loadFileChooser.setApproveButtonText("Choose Patch File To Import");

    String lastFile = Preferences.getProperty(LAST_IMPORTFILE_PREFERENCE_KEY);
    if (lastFile != null) {
      loadFileChooser.setSelectedFile(new File(lastFile));
    }
  }

  private void addLayoutAction() {
    MultiStateDockingAction<AnvillGraphLayoutProvider> layoutAction =
        new MultiStateDockingAction<>(RELAYOUT_GRAPH_ACTION_NAME, plugin.getName()) {

          @Override
          public void actionPerformed(ActionContext context) {
            // this callback is when the user clicks the button
            if (plugin.tryAcquire()) {
              AnvillGraphLayoutProvider currentUserData = getCurrentUserData();
              changeLayout(currentUserData);
              plugin.release();
            } else {
              Msg.info(this, "Could not change layout because the graph provider is busy");
            }
          }

          @Override
          public void actionStateChanged(
              ActionState<AnvillGraphLayoutProvider> newActionState, EventTrigger trigger) {
            changeLayout(newActionState.getUserData());
            if (trigger != EventTrigger.API_CALL) {
              tool.setConfigChanged(true);
            }
          }
        };
    layoutAction.setGroup("B");
    layoutAction.setHelpLocation(AnvillPatchGraphPlugin.DEFAULT_HELP);
    layoutAction.setDefaultIcon(ResourceManager.loadImage("images/preferences-system.png"));

    addLayoutProviders(layoutAction);

    addLocalAction(layoutAction);
  }

  public void changeLayout(AnvillGraphLayoutProvider newLayout) {
    layoutProvider = newLayout;
    installGraph(true);

    displayLocation(currentLocation);
    notifyContextChanged();
  }

  private void addLayoutProviders(MultiStateDockingAction<AnvillGraphLayoutProvider> layoutAction) {
    for (AnvillGraphLayoutProvider l : plugin.getLayoutProviders()) {
      layoutAction.addActionState(new ActionState<>(l.getLayoutName(), l.getActionIcon(), l));
    }
  }

  public Program getProgram() {
    return currentProgram;
  }

  public ProgramLocation getLocation() {
    return currentLocation;
  }

  private void notifyContextChanged() {
    tool.contextChanged(this);
  }

  public void programClosed(Program program) {
    storeLocation(null);
  }
}
