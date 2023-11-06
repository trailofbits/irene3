package anvill.plugin.anvillgraph;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiConsumer;

public class AnvillSlices {
  private final Map<Function, Set<Address>> slices = new ConcurrentHashMap<>();
  private final Map<Function, Set<Address>> zeroByteBlocks = new ConcurrentHashMap<>();
  private final List<AnvillSliceListener> listeners = new ArrayList<>();

  public synchronized void insertZeroByteBlock(Function function, Address address) {
    addSlice(function, address, false);
    zeroByteBlocks.putIfAbsent(function, new HashSet<>());
    zeroByteBlocks.get(function).add(address);
    notifyListeners();
  }

  public synchronized void addSlice(Function function, Address address) {
    addSlice(function, address, true);
  }

  private synchronized void addSlice(Function function, Address address, boolean notify) {
    this.slices.putIfAbsent(function, new HashSet<>());
    var addressSet = this.slices.get(function);
    addressSet.add(address);
    if (notify) this.notifyListeners();
  }

  public synchronized void removeSlice(Function function, Address address) {
    ArrayList<Map<Function, Set<Address>>> lists = new ArrayList<>();
    lists.add(slices);
    lists.add(zeroByteBlocks);

    // Remove from each list
    for (Map<Function, Set<Address>> list : lists) {
      var addressSet = list.get(function);
      if (addressSet == null) return;

      addressSet.remove(address);
      if (addressSet.isEmpty()) {
        list.remove(function);
      }
    }

    this.notifyListeners();
  }

  // Although this method is synchronized, access to the returned set isn't.
  // This can only be used within an `AnvillGraphTask` where we protect the slices from being
  // updated via a lock.
  public synchronized Set<Address> getSlices(Function function) {
    return this.slices.get(function);
  }

  // Although this method is synchronized, access to the returned set isn't.
  // This can only be used within an `AnvillGraphTask` where we protect the slices from being
  // updated via a lock.
  public synchronized Set<Address> getZeroByteBlocks(Function function) {
    return this.zeroByteBlocks.get(function);
  }

  // This method performs the entire iteration within the method so it can be used without external
  // synchronization. This is used for the UI model since a reload can be triggered at anytime.
  public synchronized void forEachSlice(
      BiConsumer<? super Function, ? super Set<Address>> function) {
    this.slices.forEach(function);
  }

  public synchronized void addListener(AnvillSliceListener listener) {
    this.listeners.add(listener);
  }

  private synchronized void notifyListeners() {
    for (AnvillSliceListener listener : this.listeners) {
      listener.onSliceUpdate(this);
    }
  }

  interface AnvillSliceListener {
    public void onSliceUpdate(AnvillSlices slices);
  }
}
