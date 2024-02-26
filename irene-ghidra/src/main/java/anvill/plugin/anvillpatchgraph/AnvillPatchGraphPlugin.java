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

import anvill.plugin.anvillpatchgraph.layout.AnvillGraphLayoutOptions;
import anvill.plugin.anvillpatchgraph.layout.AnvillGraphLayoutProvider;
import anvill.plugin.anvillpatchgraph.layout.jungrapht.JgtLayoutFactory;
import anvill.plugin.anvillpatchgraph.layout.jungrapht.JgtNamedLayoutProvider;
import anvill.plugin.anvillpatchgraph.textarea.IAnvillFunctionStateManagerProvider;
import docking.tool.ToolConstants;
import ghidra.app.decompiler.DecompilerHighlightService;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.*;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ChangeManager;
import ghidra.program.util.CodeUnitPropertyChangeRecord;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.AssertException;
import java.util.*;
import javax.swing.ImageIcon;
import resources.ResourceManager;

@PluginInfo(
    status = PluginStatus.UNSTABLE,
    packageName = PluginCategoryNames.GRAPH,
    category = PluginCategoryNames.GRAPH,
    shortDescription = AnvillPatchGraphPlugin.GRAPH_NAME,
    description =
        "Plugin to show a graphical representation of the Anvill code blocks for a function",
    servicesRequired = {
      GoToService.class,
      BlockModelService.class,
      CodeViewerService.class,
      DecompilerHighlightService.class,
      ProgramManager.class
    })
public class AnvillPatchGraphPlugin extends ProgramPlugin implements DomainObjectListener {

  public static final String GRAPH_NAME = "Anvill Patch Graph";

  public static final String SHOW_PROVIDER_ACTION_NAME = "Display Anvill Patch Graph";

  static final ImageIcon ICON = ResourceManager.loadImage("images/function_graph.png");
  static final HelpLocation DEFAULT_HELP =
      new HelpLocation("AnvillPatchGraphPlugin", "AnvillPatchGraphPlugin");
  private AnvillGraphProvider connectedProvider;
  private List<AnvillGraphProvider> disconnectedProviders = new ArrayList<>();
  private List<AnvillGraphLayoutProvider> layoutProviders;
  private anvill.plugin.anvillpatchgraph.BBGraphOptions bbGraphOptions =
      new anvill.plugin.anvillpatchgraph.BBGraphOptions();

  private List<IAnvillFunctionStateManagerProvider> stateProviders;

  private Optional<Thread> busy;

  public AnvillPatchGraphPlugin(PluginTool tool) {
    super(tool);
    this.busy = Optional.empty();
  }

  @Override
  protected void init() {
    super.init();

    layoutProviders = loadLayoutProviders();

    createNewProvider();
    initializeOptions();

    GoToService goToService = tool.getService(GoToService.class);
    this.stateProviders = new ArrayList<>();
    this.stateProviders.add(new AnvillSlicesProvider(tool, this, goToService));
    this.stateProviders.add(new AnvillSymbolsProvider(tool, this, goToService));
  }

  private void initializeOptions() {
    ToolOptions options = tool.getOptions(ToolConstants.GRAPH_OPTIONS);

    // Graph -> Anvill Graph
    Options anvillOptions = options.getOptions(GRAPH_NAME);

    bbGraphOptions.registerOptions(anvillOptions);
    bbGraphOptions.loadOptions(anvillOptions);

    for (AnvillGraphLayoutProvider layoutProvider : layoutProviders) {
      String layoutName = layoutProvider.getLayoutName();
      Options layoutToolOptions = anvillOptions.getOptions(layoutName);
      AnvillGraphLayoutOptions layoutOptions =
          layoutProvider.createLayoutOptions(layoutToolOptions);
      if (layoutOptions == null) {
        continue; // many layouts do not have options
      }

      layoutOptions.registerOptions(layoutToolOptions);
      layoutOptions.loadOptions(layoutToolOptions);
      bbGraphOptions.setLayoutOptions(layoutName, layoutOptions);
    }
  }

  private List<AnvillGraphLayoutProvider> loadLayoutProviders() {
    // add discovered layouts
    List<AnvillGraphLayoutProvider> layouts =
        ClassSearcher.getInstances(AnvillGraphLayoutProvider.class);

    // add hand-picked, generated layout providers
    List<String> jgtLayoutNames = JgtLayoutFactory.getSupportedLayoutNames();
    for (String name : jgtLayoutNames) {
      layouts.add(new JgtNamedLayoutProvider(name));
    }

    if (layouts.isEmpty()) {
      throw new AssertException(
          "Could not find any layout providers. You project may not " + "be configured properly.");
    }
    layouts.sort((o1, o2) -> -o1.getPriorityLevel() + o2.getPriorityLevel());
    return layouts;
  }

  @Override
  protected void programActivated(Program program) {
    if (connectedProvider == null) {
      return;
    }
    connectedProvider.setProgram(program);
    for (var prov : this.stateProviders) {
      prov.setProgram(program);
    }

    program.addListener(this);
  }

  @Override
  protected void programDeactivated(Program program) {
    if (connectedProvider == null) {
      return;
    }
    program.removeListener(this);
    connectedProvider.setProgram(null);
    for (var prov : this.stateProviders) {
      prov.setProgram(null);
    }
  }

  @Override
  protected void locationChanged(ProgramLocation location) {
    if (connectedProvider == null) {
      return;
    }
    connectedProvider.setProgram(currentProgram);
    connectedProvider.setLocation(location);

    for (var prov : this.stateProviders) {
      prov.setProgram(currentProgram);
      prov.setLocation(location);
    }
  }

  @Override
  protected void programClosed(Program program) {
    if (currentProgram == program) {
      currentProgram = null;
    }

    connectedProvider.programClosed(program);

    Iterator<AnvillGraphProvider> iterator = disconnectedProviders.iterator();
    while (iterator.hasNext()) {
      AnvillGraphProvider provider = iterator.next();
      if (provider.getProgram() == program) {
        iterator.remove();
        removeProvider(provider);
      }
    }
  }

  public void showProvider() {
    connectedProvider.setVisible(true);
    connectedProvider.setLocation(currentLocation);
  }

  public void closeProvider(AnvillGraphProvider provider) {
    if (provider == this.connectedProvider) {
      tool.showComponentProvider(provider, false);
    } else {
      disconnectedProviders.remove(provider);
      removeProvider(provider);
    }
  }

  private void createNewProvider() {
    connectedProvider = new AnvillGraphProvider(this, true);
    connectedProvider.setProgram(currentProgram);
    connectedProvider.setLocation(currentLocation);
  }

  public AnvillGraphProvider createNewDisconnectedProvider() {
    AnvillGraphProvider provider = new AnvillGraphProvider(this, false);
    disconnectedProviders.add(provider);
    tool.showComponentProvider(provider, true);
    return provider;
  }

  @Override
  protected void dispose() {
    super.dispose();
    currentProgram = null;

    removeProvider(connectedProvider);
    for (AnvillGraphProvider provider : disconnectedProviders) {
      removeProvider(provider);
    }
    disconnectedProviders.clear();
    for (var prov : this.stateProviders) {
      prov.dispose();
    }
  }

  private void removeProvider(AnvillGraphProvider provider) {
    if (provider == null) {
      return;
    }
    provider.dispose();
    tool.removeComponentProvider(provider);
  }

  public List<AnvillGraphLayoutProvider> getLayoutProviders() {
    return Collections.unmodifiableList(layoutProviders);
  }

  public BBGraphOptions getGraphOptions() {
    return bbGraphOptions;
  }

  public synchronized boolean tryAcquire() {
    if (busy.isPresent()) {
      return false;
    }
    busy = Optional.of(Thread.currentThread());
    return true;
  }

  public synchronized void release() {
    if (busy.isPresent() && Thread.currentThread() == busy.get()) {
      busy = Optional.empty();
    }
  }

  @Override
  public void domainObjectChanged(DomainObjectChangedEvent domainObjectChangedEvent) {
    if (domainObjectChangedEvent.containsEvent(ChangeManager.DOCR_CODE_UNIT_PROPERTY_CHANGED)) {
      var iter = domainObjectChangedEvent.iterator();
      while (iter.hasNext()) {
        var n = iter.next();
        if (n.getEventType() == ChangeManager.DOCR_CODE_UNIT_PROPERTY_CHANGED) {
          var prop = (CodeUnitPropertyChangeRecord) n;
          for (var prov : this.stateProviders) {
            var listeners = prov.listeners();
            if (listeners.containsKey(prop.getPropertyName())) {
              for (var list : listeners.get(prop.getPropertyName())) {
                list.onStateUpdate();
              }
            }
          }
        }
      }
    }
  }
}
