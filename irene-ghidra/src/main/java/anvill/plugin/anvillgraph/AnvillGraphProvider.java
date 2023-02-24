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
package anvill.plugin.anvillgraph;

import anvill.plugin.anvillgraph.AnvillPatchInfo.Patch;
import anvill.plugin.anvillgraph.graph.*;
import anvill.plugin.anvillgraph.graph.jung.renderer.AnvillEdgePaintTransformer;
import anvill.plugin.anvillgraph.layout.AnvillGraphLayoutProvider;
import anvill.plugin.anvillgraph.layout.BBGraphLayout;
import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.EventTrigger;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import edu.uci.ics.jung.visualization.RenderContext;
import ghidra.app.nav.DecoratorPanel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.preferences.Preferences;
import ghidra.graph.VisualGraphComponentProvider;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.renderer.VisualGraphEdgeLabelRenderer;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.filechooser.GhidraFileFilter;
import ghidra.util.task.*;
import java.awt.Color;
import java.io.*;
import java.nio.file.Files;
import java.util.*;
import javax.swing.JComponent;
import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.DualHashBidiMap;
import resources.Icons;
import resources.ResourceManager;

public class AnvillGraphProvider extends
    VisualGraphComponentProvider<BasicBlockVertex, BasicBlockEdge, BasicBlockGraph> {

  public static final String LAST_IMPORTFILE_PREFERENCE_KEY = "AnvillGraphProvider.ImportFile";
  public static final String LAST_SAVEFILE_PREFERENCE_KEY = "AnvillGraphProvider.SaveFile";
  public static final String RELAYOUT_GRAPH_ACTION_NAME = "Relayout Graph";
  public static final String LOAD_PATCHES_ACTION_NAME = "Load Patch File";
  public static final String SAVE_PATCHES_ACTION_NAME = "Save Patches";
  private final GhidraFileFilter JSON_FILE_FILTER =
      ExtensionFileFilter.forExtensions("JSON files", "json");
  private final PluginTool tool;
  private final AnvillGraphPlugin plugin;
  private DecoratorPanel decorationPanel;
  private Program currentProgram;
  private BasicBlockGraph graph;
  private ProgramLocation currentLocation;
  private VisualGraphView<BasicBlockVertex, BasicBlockEdge, BasicBlockGraph> view;
  private AnvillGraphLayoutProvider layoutProvider;
  private boolean isConnected;
  private GhidraFileChooser loadFileChooser;
  private GhidraFileChooser saveFileChooser;
  private AnvillPatchInfo anvillPatchInfo;
  private ProgramLocation pendingLocation;
  private SwingUpdateManager updateLocationUpdateManager;

  public AnvillGraphProvider(AnvillGraphPlugin anvillGraphPlugin, boolean isConnected) {
    super(anvillGraphPlugin.getTool(), AnvillGraphPlugin.GRAPH_NAME, anvillGraphPlugin.getName());

    this.tool = anvillGraphPlugin.getTool();
    this.plugin = anvillGraphPlugin;

    // View is handled by FGController in upstream
    view = new VisualGraphView<>();
    // these default to off; they are typically controlled via a UI element; the
    // values set here are arbitrary and are for demo purposes
    view.setVertexFocusPathHighlightMode(PathHighlightMode.OUT);
    view.setVertexHoverPathHighlightMode(PathHighlightMode.IN);

    setConnected(isConnected);
    setIcon(AnvillGraphPlugin.ICON);

    if (!isConnected) {
      setTransient();
    } else {
      addToToolbar();
    }

    decorationPanel = new DecoratorPanel(view.getViewComponent(), isConnected);
    setWindowMenuGroup(AnvillGraphPlugin.GRAPH_NAME);
    setWindowGroup(AnvillGraphPlugin.GRAPH_NAME);
    setDefaultWindowPosition(WindowPosition.WINDOW);

    setHelpLocation(AnvillGraphPlugin.DEFAULT_HELP);

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

  /**
   * Install/build the graph, rebuilding when necessary
   */
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
    RenderContext<BasicBlockVertex, BasicBlockEdge> renderContext = view.getPrimaryGraphViewer()
        .getRenderContext();
    AnvillEdgePaintTransformer edgePaintTransformer = new AnvillEdgePaintTransformer(
        getAnvillGraphOptions());
    renderContext.setEdgeDrawPaintTransformer(edgePaintTransformer);
    renderContext.setArrowDrawPaintTransformer(edgePaintTransformer);
    renderContext.setArrowFillPaintTransformer(edgePaintTransformer);

    // edge label rendering
    com.google.common.base.Function<BasicBlockEdge, String> edgeLabelTransformer = BasicBlockEdge::getLabel;
    renderContext.setEdgeLabelTransformer(edgeLabelTransformer);

    // note: this label renderer is the stamp for the label; we use another edge label
    //       renderer inside of the VisualGraphRenderer
    VisualGraphEdgeLabelRenderer edgeLabelRenderer =
        new VisualGraphEdgeLabelRenderer(Color.BLACK);
    edgeLabelRenderer.setNonPickedForegroundColor(Color.LIGHT_GRAY);
    edgeLabelRenderer.setRotateEdgeLabels(false);
    renderContext.setEdgeLabelRenderer(edgeLabelRenderer);
  }

  public void setProgram(Program newProgram) {
    currentProgram = newProgram;
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
          graph.setVertexFocused(newVertex, true);
          view.getViewUpdater().moveVertexToCenterWithAnimation(newVertex);
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
    Function function = currentProgram.getFunctionManager()
        .getFunctionContaining(currentLocation.getAddress());
    if (function == null) {
      Msg.info(getClass(), "No function at current location: " + currentLocation);
      graph = null;
      return;
    }

    AddressSetView addresses = function.getBody();

    // Prepare our patch info mappings
    Map<Address, Patch> patches = new HashMap<>();
    for (Patch patch : anvillPatchInfo.getPatches()) {
      Address patchAddr = currentProgram.getAddressFactory().getAddress(patch.getAddress());
      patches.put(patchAddr, patch);
    }
    graph = new BasicBlockGraph(function);

    TaskMonitor monitor = new DummyCancellableTaskMonitor();

    // TODO: See FunctionGraphFactory for more complete details
    // **** Vertices
    BidiMap<CodeBlock, BasicBlockVertex> vertices = new DualHashBidiMap<>();
    CodeBlockModel blockModel = new BasicBlockModel(currentProgram);

    CodeBlockIterator iterator = blockModel.getCodeBlocksContaining(addresses, monitor);
    monitor.initialize(addresses.getNumAddresses());

    while (iterator.hasNext()) {
      CodeBlock codeBlock = iterator.next();
      Address startingAddr = codeBlock.getFirstStartAddress();
      Patch patch = patches.get(startingAddr);
      if (patch == null) {
        Msg.info(this,
            "This function contains a basic block address that has no corresponding patch: "
                + startingAddr);
        graph = null;
        return;
      }

      BasicBlockVertex vertex = new AnvillVertex(codeBlock, patch);
      vertices.put(codeBlock, vertex);

      long blockAddressCount = codeBlock.getNumAddresses();
      long currentProgress = monitor.getProgress();
      monitor.setProgress(currentProgress + blockAddressCount);
    }

    // **** Edges
    Collection<BasicBlockEdge> edges = new ArrayList<>();
    for (BasicBlockVertex startVertex : vertices.values()) {
      CodeBlock codeBlock = vertices.getKey(startVertex);
      CodeBlockReferenceIterator destinations = codeBlock.getDestinations(monitor);
      while (destinations.hasNext()) {
        CodeBlockReference reference = destinations.next();
        CodeBlock destinationBlock = reference.getDestinationBlock();
        BasicBlockVertex destinationVertex = vertices.get(destinationBlock);
        if (destinationVertex == null) {
          continue;  // no vertex means the code block is not in our function
        }

        edges.add(new AnvillEdge(startVertex, destinationVertex, reference.getFlowType()));
      }
    }

    // **** Graph
    vertices.values().forEach(v -> graph.addVertex(v));
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

  public void dispose() {
    removeFromTool();
  }

  @Override
  public VisualGraphView<BasicBlockVertex, BasicBlockEdge, BasicBlockGraph> getView() {
    return view;
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

  private void createActions() {
    DockingAction loadPatches = new DockingAction(LOAD_PATCHES_ACTION_NAME, plugin.getName()) {
      @Override
      public void actionPerformed(ActionContext context) {
        importPatchesAction();
      }
    };
    loadPatches.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
    loadPatches.setEnabled(true);
    loadPatches.markHelpUnnecessary();
    addLocalAction(loadPatches);

    DockingAction savePatchesAction = new DockingAction(SAVE_PATCHES_ACTION_NAME,
        plugin.getName()) {
      @Override
      public void actionPerformed(ActionContext context) {
        savePatches();
      }
    };
    savePatchesAction.setToolBarData(
        new ToolBarData(ResourceManager.loadImage("images/disk_save_as.png"), null));
    // TODO: Only enable if something is loaded
    savePatchesAction.setEnabled(true);
    savePatchesAction.markHelpUnnecessary();
    addLocalAction(savePatchesAction);

    addLayoutAction();
  }

  private void savePatches() {
    if (anvillPatchInfo == null) {
      Msg.showError(this, view.getPrimaryGraphViewer(), "Nothing to Save",
          "There is no patch data to save.");
      return;
    }

    updatePatchModel();
    if (!anvillPatchInfo.isModified()) {
      Msg.showError(this, view.getPrimaryGraphViewer(), "No Changes",
          "Patch data has not changed. Nothing to save.");
      return;
    }

    // Initialize file chooser
    if (saveFileChooser == null) {
      saveFileChooser = new GhidraFileChooser(tool.getActiveWindow());
      saveFileChooser.addFileFilter(JSON_FILE_FILTER);
      saveFileChooser.setSelectedFileFilter(JSON_FILE_FILTER);
    }
    String lastSaveFile = Preferences.getProperty(LAST_SAVEFILE_PREFERENCE_KEY);
    if (lastSaveFile != null) {
      saveFileChooser.setSelectedFile(new File(lastSaveFile));
    }

    // Do something with chosen file
    File saveAsFile = saveFileChooser.getSelectedFile();
    if (saveAsFile == null) {
      return;
    }
    boolean exists = saveAsFile.exists();
    if (exists) {
      int result = OptionDialog.showYesNoDialog(view.getPrimaryGraphViewer(), getName(),
          "Do you want to OVERWRITE the following file:\n" + saveAsFile.getName());
      if (result != OptionDialog.OPTION_ONE) {
        return;
      }
    }
    try {
      String str = anvillPatchInfo.serialize();
      PrintWriter writer = new PrintWriter(new FileWriter(saveAsFile));
      writer.println(str);
      writer.close();

      Preferences.setProperty(LAST_SAVEFILE_PREFERENCE_KEY, saveAsFile.getAbsolutePath());
      Preferences.store();

      Msg.showInfo(this, view.getPrimaryGraphViewer(), "", "Saved!");
    } catch (IOException e) {
      Msg.showError(this, view.getPrimaryGraphViewer(), "Error Saving File As...", e.getMessage());
    }
  }

  /**
   * Update patch models with potentially user-changed text in the graph vertices.
   */
  public void updatePatchModel() {
    if (graph == null || anvillPatchInfo == null) {
      return;
    }
    for (BasicBlockVertex v : graph.getVertices()) {
      // We know our graph is full of Anvill vertices
      AnvillVertex av = (AnvillVertex) v;
      Patch patch = av.getPatch();
      patch.setCode(av.getTextArea().getText());
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
      Msg.showInfo(this, tool.getActiveWindow(), "File does not exist.",
          "File does not exist: " + file.getAbsolutePath());
    } else {
      importPatchesFile(file);
    }
  }

  void importPatchesFile(File file) {
    anvillPatchInfo = null;
    String fileContent;
    try {
      fileContent = new String(Files.readAllBytes(file.toPath()));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    try {
      anvillPatchInfo = new AnvillPatchInfo(fileContent);
    } catch (InstantiationException e) {
      Msg.showError(this, tool.getActiveWindow(), "Bad Patch",
          "Could not import patch: " + e.getMessage());
      anvillPatchInfo = null;
      return;
    }
    Preferences.setProperty(LAST_IMPORTFILE_PREFERENCE_KEY, file.getAbsolutePath());
    Preferences.store();
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
          protected void doActionPerformed(ActionContext context) {
            // this callback is when the user clicks the button
            AnvillGraphLayoutProvider currentUserData = getCurrentUserData();
            changeLayout(currentUserData);
          }

          @Override
          public void actionStateChanged(
              ActionState<AnvillGraphLayoutProvider> newActionState,
              EventTrigger trigger) {
            changeLayout(newActionState.getUserData());
            if (trigger != EventTrigger.API_CALL) {
              tool.setConfigChanged(true);
            }
          }
        };
    layoutAction.setGroup("B");
    layoutAction.setHelpLocation(AnvillGraphPlugin.DEFAULT_HELP);
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

  private void addLayoutProviders(
      MultiStateDockingAction<AnvillGraphLayoutProvider> layoutAction) {
    for (AnvillGraphLayoutProvider l : plugin.getLayoutProviders()) {
      layoutAction.addActionState(new ActionState<>(l.getLayoutName(), l.getActionIcon(), l));
    }
  }

  public Program getProgram() {
    return currentProgram;
  }

  private void notifyContextChanged() {
    tool.contextChanged(this);
  }

  public void programClosed(Program program) {
    storeLocation(null);
  }
}
