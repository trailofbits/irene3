package anvill.plugin.anvillpatchgraph;

import anvill.plugin.anvillpatchgraph.textarea.IAnvillFunctionStateManagerProvider;
import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.services.GoToService;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraThreadedTablePanel;
import ghidra.util.task.TaskMonitor;
import java.util.*;
import javax.swing.*;
import resources.Icons;
import resources.ResourceManager;

public abstract class AnvillFunctionStateManagerProvider<T extends Comparable<T>>
    extends ComponentProviderAdapter implements IAnvillFunctionStateManagerProvider {
  static final ImageIcon ICON = ResourceManager.loadImage("images/table.png");
  private AnvillPatchGraphPlugin plugin;
  private GhidraTable sliceTable;
  private AnvillFunctionStateManagerProvider.SliceTableModel model;

  private Optional<StateManager<T>> splits;

  private final Map<String, List<AnvillStateUpdateListener>> sliceListeners;
  private final String name;

  private GhidraThreadedTablePanel<AnvillFunctionStateManagerProvider.SliceRowObject>
      threadedTablePanel;

  AnvillFunctionStateManagerProvider(
      String name, PluginTool tool, AnvillPatchGraphPlugin plugin, GoToService goToService) {
    super(tool, "Anvill " + name, plugin.getName(), ProgramActionContext.class);
    this.plugin = plugin;
    this.name = name;
    this.splits = Optional.empty();
    this.model = new SliceTableModel(tool, plugin);
    this.sliceListeners = new HashMap<>();

    this.addListener(this.model);
    this.threadedTablePanel = new GhidraThreadedTablePanel<>(model);
    this.sliceTable = this.threadedTablePanel.getTable();
    this.sliceTable.installNavigation(goToService, goToService.getDefaultNavigatable());
    setIcon(this.ICON);
    setDefaultWindowPosition(WindowPosition.BOTTOM);
    DockingAction deleteSlice =
        new anvill.plugin.anvillpatchgraph.AnvillGraphAction(plugin, "Delete " + name) {
          @Override
          public void runInAction(TaskMonitor taskMonitor, ActionContext context) {
            deleteSliceAction();
          }
        };
    deleteSlice.setToolBarData(new ToolBarData(Icons.DELETE_ICON, null));
    deleteSlice.setEnabled(true);
    deleteSlice.markHelpUnnecessary();
    addLocalAction(deleteSlice);
    addToToolbar();
    addToTool();
  }

  private void addListener(AnvillStateUpdateListener list) {
    for (var k : this.UsedPropertyKeys()) {
      this.sliceListeners.putIfAbsent(k, new ArrayList<>());
      var lst = this.sliceListeners.get(k);
      lst.add(list);
    }
  }

  public abstract List<String> UsedPropertyKeys();

  protected Optional<Function> getTargetFunction() {
    return this.model.target_func;
  }

  public Map<String, List<AnvillStateUpdateListener>> listeners() {
    return this.sliceListeners;
  }

  public void setLocation(ProgramLocation loc) {
    if (Objects.isNull(loc)) {
      this.model.clearFunction();
      return;
    }
    if (!Objects.isNull(this.model.getProgram())) {
      var f = this.model.getProgram().getFunctionManager().getFunctionContaining(loc.getAddress());
      if (Objects.isNull(f)) {
        this.model.clearFunction();
      } else {
        this.model.setFunction(f);
      }
    }
  }

  public abstract Optional<Address> addressOfElement(T t);

  public abstract StateManager<T> buildManager(Program program);

  public void setProgram(Program program) {
    this.model.setProgram(program);
    this.model.reload();
    if (Objects.isNull(program)) {
      this.splits = Optional.empty();
    } else {
      this.splits = Optional.of(buildManager(program));
    }
  }

  public void dispose() {
    removeFromTool();
  }

  private void deleteSliceAction() {
    int[] rows = sliceTable.getSelectedRows();
    List<AnvillFunctionStateManagerProvider<T>.SliceRowObject> sliceObjects =
        model.getRowObjects(rows);
    if (splits.isPresent()) {
      for (AnvillFunctionStateManagerProvider<T>.SliceRowObject slice : sliceObjects) {
        splits.get().attemptRemove(slice.getFunction().getEntryPoint(), slice.getElem());
      }
      model.reload();
    }
  }

  @Override
  public JComponent getComponent() {
    return threadedTablePanel;
  }

  class SliceTableModel
      extends AddressBasedTableModel<AnvillFunctionStateManagerProvider<T>.SliceRowObject>
      implements AnvillStateUpdateListener {
    private AnvillPatchGraphPlugin plugin;

    private Optional<Function> target_func;

    SliceTableModel(PluginTool tool, AnvillPatchGraphPlugin plugin) {
      super(name, tool, plugin.getCurrentProgram(), null);
      this.plugin = plugin;
      this.target_func = Optional.empty();
    }

    public void clearFunction() {
      this.target_func = Optional.empty();
    }

    public void setFunction(Function func) {
      this.target_func = Optional.of(func);
      this.reload();
    }

    @Override
    protected void doLoad(
        Accumulator<AnvillFunctionStateManagerProvider<T>.SliceRowObject> accumulator,
        TaskMonitor taskMonitor)
        throws CancelledException {
      if (splits.isPresent() && target_func.isPresent()) {
        for (var addr : splits.get().getApplicableRows(target_func.get().getEntryPoint())) {
          accumulator.add(
              new AnvillFunctionStateManagerProvider<T>.SliceRowObject(
                  this.target_func.get(), addr));
        }
      }
    }

    @Override
    protected TableColumnDescriptor<AnvillFunctionStateManagerProvider<T>.SliceRowObject>
        createTableColumnDescriptor() {
      TableColumnDescriptor<AnvillFunctionStateManagerProvider<T>.SliceRowObject> descriptor =
          new TableColumnDescriptor<>();
      descriptor.addVisibleColumn(
          new AnvillFunctionStateManagerProvider<T>.SliceTableModel.FunctionNameTableColumn());
      descriptor.addVisibleColumn(
          new AnvillFunctionStateManagerProvider<T>.SliceTableModel.AddressTableColumn());
      return descriptor;
    }

    @Override
    public Address getAddress(int row) {
      if (row < this.allData.size()) {
        var r = this.allData.get(row);
        var maybe_addr = addressOfElement(r.getElem());
        if (maybe_addr.isPresent()) {
          return maybe_addr.get();
        }
      }
      return null;
    }

    @Override
    public void onStateUpdate() {
      this.reload();
    }

    class FunctionNameTableColumn
        extends AbstractDynamicTableColumn<
            AnvillFunctionStateManagerProvider<T>.SliceRowObject, String, Object> {
      @Override
      public String getColumnName() {
        return "Function";
      }

      @Override
      public String getValue(
          AnvillFunctionStateManagerProvider.SliceRowObject sliceRowObject,
          Settings settings,
          Object o,
          ServiceProvider serviceProvider)
          throws IllegalArgumentException {
        return sliceRowObject.getFunction().getName();
      }
    }

    class AddressTableColumn
        extends AbstractDynamicTableColumn<
            AnvillFunctionStateManagerProvider<T>.SliceRowObject, String, Object> {
      @Override
      public String getColumnName() {
        return name;
      }

      @Override
      public String getValue(
          AnvillFunctionStateManagerProvider.SliceRowObject sliceRowObject,
          Settings settings,
          Object o,
          ServiceProvider serviceProvider)
          throws IllegalArgumentException {
        return sliceRowObject.getElem().toString();
      }
    }
  }

  class SliceRowObject implements Comparable<AnvillFunctionStateManagerProvider<T>.SliceRowObject> {
    private Function function;
    private T elem;

    SliceRowObject(Function function, T elem) {
      this.function = function;
      this.elem = elem;
    }

    public Function getFunction() {
      return function;
    }

    public T getElem() {
      return elem;
    }

    @Override
    public int compareTo(AnvillFunctionStateManagerProvider<T>.SliceRowObject o) {
      int funcCompare = this.function.toString().compareTo(o.function.toString());
      if (funcCompare != 0) {
        return funcCompare;
      }
      return this.elem.compareTo(o.elem);
    }
  }
}
