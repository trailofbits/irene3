package anvill.plugin.anvillpatchgraph;

import ghidra.program.model.address.Address;

public interface StateManager<T> {
  java.util.Set<T> getApplicableRows(Address addr);

  void attemptRemove(Address addr, T elem);
}
