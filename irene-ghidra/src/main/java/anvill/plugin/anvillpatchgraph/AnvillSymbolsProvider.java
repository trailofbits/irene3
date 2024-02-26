package anvill.plugin.anvillpatchgraph;

import anvill.RequiredSymbolsManager;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import resources.Icons;

public class AnvillSymbolsProvider extends AnvillFunctionStateManagerProvider<String> {
  private Optional<RequiredSymbolsManager> man;

  AnvillSymbolsProvider(PluginTool tool, AnvillPatchGraphPlugin plugin, GoToService goToService) {
    super("Required Symbols", tool, plugin, goToService);

    DockingAction addReqSym =
        new anvill.plugin.anvillpatchgraph.AnvillGraphAction(plugin, "Add Required Symbol") {
          @Override
          public void runInAction(TaskMonitor taskMonitor, ActionContext context) {
            addRequiredSymAction();
          }
        };
    addReqSym.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
    addReqSym.setEnabled(true);
    addReqSym.markHelpUnnecessary();
    addLocalAction(addReqSym);
    man = Optional.empty();
  }

  private void addRequiredSymAction() {
    var sym_name = new GlobalNameInputDialogComponentProvider("Add reference to global");
    if (sym_name.isCanceled()) {
      return;
    }

    var target_func = this.getTargetFunction();
    if (this.man.isPresent() && target_func.isPresent()) {
      var nm = sym_name.getGlobalName();
      this.man.get().addSymbol(target_func.get().getEntryPoint(), nm);
    }
  }

  @Override
  public List<String> UsedPropertyKeys() {
    return Arrays.asList(RequiredSymbolsManager.REQ_SYMS());
  }

  @Override
  public Optional<Address> addressOfElement(String address) {
    return Optional.empty();
  }

  @Override
  public StateManager<String> buildManager(Program program) {
    var sp = new RequiredSymbolsManager(program);
    this.man = Optional.of(sp);
    return new StateManager<>() {

      @Override
      public Set<String> getApplicableRows(Address addr) {
        return sp.getRequiredSymbols(addr);
      }

      @Override
      public void attemptRemove(Address addr, String elem) {
        sp.removeSymbol(addr, elem);
      }
    };
  }
}
