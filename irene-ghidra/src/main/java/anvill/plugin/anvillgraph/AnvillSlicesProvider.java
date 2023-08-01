package anvill.plugin.anvillgraph;

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
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraThreadedTablePanel;
import ghidra.util.task.TaskMonitor;
import java.util.List;
import javax.swing.*;
import resources.Icons;
import resources.ResourceManager;

public class AnvillSlicesProvider extends ComponentProviderAdapter {
  static final ImageIcon ICON = ResourceManager.loadImage("images/table.png");
  private AnvillGraphPlugin plugin;
  private GhidraTable sliceTable;
  private SliceTableModel model;
  private GhidraThreadedTablePanel<SliceRowObject> threadedTablePanel;

  AnvillSlicesProvider(PluginTool tool, AnvillGraphPlugin plugin, GoToService goToService) {
    super(tool, "Anvill Slices", plugin.getName(), ProgramActionContext.class);
    this.plugin = plugin;
    this.model = new SliceTableModel(tool, plugin);
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

  public void setProgram(Program program) {
    this.model.setProgram(program);
    this.model.reload();
  }

  public void dispose() {
    removeFromTool();
  }

  private void deleteSliceAction() {
    int[] rows = sliceTable.getSelectedRows();
    List<SliceRowObject> sliceObjects = model.getRowObjects(rows);
    for (SliceRowObject slice : sliceObjects) {
      this.plugin.getFunctionSlices().removeSlice(slice.getFunction(), slice.getAddress());
    }
    model.reload();
  }

  @Override
  public JComponent getComponent() {
    return threadedTablePanel;
  }

  class SliceTableModel extends AddressBasedTableModel<SliceRowObject>
      implements AnvillSlices.AnvillSliceListener {
    private AnvillGraphPlugin plugin;

    SliceTableModel(PluginTool tool, AnvillGraphPlugin plugin) {
      super("Slices", tool, plugin.getCurrentProgram(), null);
      this.plugin = plugin;
      this.plugin.getFunctionSlices().addListener(this);
    }

    @Override
    public void onSliceUpdate(AnvillSlices slices) {
      this.reload();
    }

    @Override
    protected void doLoad(Accumulator<SliceRowObject> accumulator, TaskMonitor taskMonitor)
        throws CancelledException {
      this.plugin
          .getFunctionSlices()
          .forEachSlice(
              (function, addresses) -> {
                if (function.getProgram() != this.getProgram()) {
                  return;
                }
                for (Address address : addresses) {
                  accumulator.add(new SliceRowObject(function, address));
                }
              });
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
