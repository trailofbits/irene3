package anvill.plugin.anvillgraph.actions;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.plugin.core.decompile.DecompilePlugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.Msg;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class AddToPatchSliceAction extends DockingAction {
  private final Map<Function, Set<Address>> saveList;

  public AddToPatchSliceAction(Map<Function, Set<Address>> save_list) {
    super("Add Patch To Slice", DecompilePlugin.class.getSimpleName());
    this.saveList = save_list;
    setPopupMenuData(new MenuData(new String[] {"Add selection to slice"}, "New"));
    setDescription("Adds selection to the working patch slice for this function");
  }

  @Override
  public void actionPerformed(ActionContext actionContext) {
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
      saveList.putIfAbsent(func, new HashSet<>());
      var targetSet = saveList.get(func);
      targetSet.add(minSplit);
      targetSet.add(maxSplit);
      Msg.debug(
          this,
          "Added selection between "
              + minSplit.toString()
              + " and "
              + maxSplit.toString()
              + " for "
              + func.getName());
    }
  }
}
