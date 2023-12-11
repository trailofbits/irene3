package anvill.plugin.anvillgraph;

import anvill.SplitsManager;
import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.OkDialog;
import docking.widgets.OptionDialog;
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
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.swing.*;
import resources.Icons;
import resources.ResourceManager;

public class AnvillSlicesProvider extends ComponentProviderAdapter {
  static final ImageIcon ICON = ResourceManager.loadImage("images/table.png");
  private AnvillGraphPlugin plugin;
  private GhidraTable sliceTable;
  private SliceTableModel model;

  private Optional<SplitsManager> splits;

  private final List<AnvillSliceListener> sliceListeners;

  private GhidraThreadedTablePanel<SliceRowObject> threadedTablePanel;

  AnvillSlicesProvider(PluginTool tool, AnvillGraphPlugin plugin, GoToService goToService) {
    super(tool, "Anvill Slices", plugin.getName(), ProgramActionContext.class);
    this.plugin = plugin;
    this.splits = Optional.empty();
    this.model = new SliceTableModel(tool, plugin);
    this.sliceListeners = new ArrayList<>();
    this.sliceListeners.add(this.model);
    this.threadedTablePanel = new GhidraThreadedTablePanel<>(model);
    this.sliceTable = this.threadedTablePanel.getTable();
    this.sliceTable.installNavigation(goToService, goToService.getDefaultNavigatable());
    setIcon(this.ICON);
    setDefaultWindowPosition(WindowPosition.BOTTOM);
    DockingAction deleteSlice =
        new AnvillGraphAction(plugin, "Delete Slice") {
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

  public List<AnvillSliceListener> listeners() {
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

  public void setProgram(Program program) {
    this.model.setProgram(program);
    this.model.reload();
    if (Objects.isNull(program)) {
      this.splits = Optional.empty();
    } else {
      this.splits = Optional.of(new SplitsManager(program));
    }
  }

  public void dispose() {
    removeFromTool();
  }

  private void deleteSliceAction() {
    int[] rows = sliceTable.getSelectedRows();
    List<SliceRowObject> sliceObjects = model.getRowObjects(rows);
    if (splits.isPresent()) {
      for (SliceRowObject slice : sliceObjects) {
        if (splits
            .get()
            .getZeroBlocksForAddress(slice.getFunction().getEntryPoint())
            .contains(slice.getAddress())) {
          var confirmDialog =
              new OkDialog(
                  "Attention!",
                  "This address is a zero-byte block. Are you sure you want to remove this split?",
                  OptionDialog.WARNING_MESSAGE);
          tool.showDialog(confirmDialog);
          if (confirmDialog.getResult() == OptionDialog.CANCEL_OPTION) return;
        }

        splits.get().removeSplitForAddress(slice.getFunction().getEntryPoint(), slice.getAddress());
        splits
            .get()
            .removeZeroBlockForAddress(slice.getFunction().getEntryPoint(), slice.getAddress());
      }
      model.reload();
    }
  }

  @Override
  public JComponent getComponent() {
    return threadedTablePanel;
  }

  class SliceTableModel extends AddressBasedTableModel<SliceRowObject>
      implements AnvillSliceListener {
    private AnvillGraphPlugin plugin;

    private Optional<Function> target_func;

    SliceTableModel(PluginTool tool, AnvillGraphPlugin plugin) {
      super("Slices", tool, plugin.getCurrentProgram(), null);
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
    protected void doLoad(Accumulator<SliceRowObject> accumulator, TaskMonitor taskMonitor)
        throws CancelledException {
      if (splits.isPresent() && target_func.isPresent()) {
        for (var addr : splits.get().getSplitsForAddressJava(target_func.get().getEntryPoint())) {
          accumulator.add(new SliceRowObject(this.target_func.get(), addr));
        }
      }
    }

    @Override
    protected TableColumnDescriptor<SliceRowObject> createTableColumnDescriptor() {
      TableColumnDescriptor<SliceRowObject> descriptor = new TableColumnDescriptor<>();
      descriptor.addVisibleColumn(new FunctionNameTableColumn());
      descriptor.addVisibleColumn(new AddressTableColumn());
      return descriptor;
    }

    @Override
    public Address getAddress(int row) {
      if (row < this.allData.size()) {
        return this.allData.get(row).getAddress();
      }
      return null;
    }

    @Override
    public void onSliceUpdate() {
      this.reload();
    }

    class FunctionNameTableColumn
        extends AbstractDynamicTableColumn<SliceRowObject, String, Object> {
      @Override
      public String getColumnName() {
        return "Function";
      }

      @Override
      public String getValue(
          SliceRowObject sliceRowObject,
          Settings settings,
          Object o,
          ServiceProvider serviceProvider)
          throws IllegalArgumentException {
        return sliceRowObject.getFunction().getName();
      }
    }

    class AddressTableColumn extends AbstractDynamicTableColumn<SliceRowObject, String, Object> {
      @Override
      public String getColumnName() {
        return "Address";
      }

      @Override
      public String getValue(
          SliceRowObject sliceRowObject,
          Settings settings,
          Object o,
          ServiceProvider serviceProvider)
          throws IllegalArgumentException {
        return sliceRowObject.getAddress().toString();
      }
    }
  }

  class SliceRowObject implements Comparable<SliceRowObject> {
    private Function function;
    private Address address;

    SliceRowObject(Function function, Address address) {
      this.function = function;
      this.address = address;
    }

    public Function getFunction() {
      return function;
    }

    public Address getAddress() {
      return address;
    }

    @Override
    public int compareTo(SliceRowObject o) {
      int funcCompare = this.function.toString().compareTo(o.function.toString());
      if (funcCompare != 0) {
        return funcCompare;
      }
      return this.address.compareTo(o.address);
    }
  }
}
