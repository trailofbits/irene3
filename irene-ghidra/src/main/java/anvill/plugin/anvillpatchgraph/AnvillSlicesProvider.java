package anvill.plugin.anvillpatchgraph;

import anvill.SplitsManager;
import docking.widgets.OkDialog;
import docking.widgets.OptionDialog;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import java.util.*;
import javax.swing.*;

public class AnvillSlicesProvider extends AnvillFunctionStateManagerProvider<Address> {
  AnvillSlicesProvider(PluginTool tool, AnvillPatchGraphPlugin plugin, GoToService goToService) {
    super("Slices", tool, plugin, goToService);
  }

  @Override
  public List<String> UsedPropertyKeys() {
    return Arrays.asList(
        anvill.SplitsManager.SPLITS_MAP(), anvill.SplitsManager.ZERO_BYTE_BLOCKS());
  }

  @Override
  public Optional<Address> addressOfElement(Address address) {
    return Optional.of(address);
  }

  @Override
  public StateManager<Address> buildManager(Program program) {
    return new StateManager<>() {
      private SplitsManager sp = new SplitsManager(program);

      @Override
      public Set<Address> getApplicableRows(Address addr) {
        return sp.getSplitsForAddressJava(addr);
      }

      @Override
      public void attemptRemove(Address addr, Address elem) {
        if (sp.getZeroBlocksForAddress(addr).contains(elem)) {
          var confirmDialog =
              new OkDialog(
                  "Attention!",
                  "This address is a zero-byte block. Are you sure you want to remove this split?",
                  OptionDialog.WARNING_MESSAGE);
          tool.showDialog(confirmDialog);
          if (confirmDialog.getResult() == OptionDialog.CANCEL_OPTION) return;
        }

        sp.removeSplitForAddress(addr, elem);
        sp.removeZeroBlockForAddress(addr, elem);
      }
    };
  }
}
