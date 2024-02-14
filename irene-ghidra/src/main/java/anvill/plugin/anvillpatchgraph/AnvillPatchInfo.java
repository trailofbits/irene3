package anvill.plugin.anvillpatchgraph;

import com.google.gson.*;
import irene3.server.PatchService;
import java.util.*;

public class AnvillPatchInfo {

  private final List<Patch> patches = new ArrayList<>();

  public AnvillPatchInfo(PatchService.PatchGraph patchGraph) throws InstantiationException {
    patchGraph.getBlocksMap().forEach((aLong, patchBlock) -> patches.add(new Patch(patchBlock)));
  }

  public List<Patch> getPatches() {
    return patches;
  }

  public static class Patch {
    private final PatchService.PatchBlock orig;
    private String code;
    private boolean modified;

    Patch(PatchService.PatchBlock patchBlock) {
      this.orig = PatchService.PatchBlock.newBuilder(patchBlock).build();
      this.code = orig.getCode();
      this.modified = false;
    }

    public String serializePatchInfo() {
      var ret = PatchService.PatchBlock.newBuilder(orig).setCode(code).build();
      // TODO(ekilmer): How to serialize this?
      return ret.toString();
    }

    public synchronized boolean isModified() {
      return modified;
    }

    public String getAddress() {
      long addr = orig.getAddress();
      return Long.toHexString(addr);
    }

    public long getSize() {
      return orig.getSize();
    }

    public long getUid() {
      return orig.getUid();
    }

    public String getCode() {
      return code;
    }

    public synchronized void setCode(String newCode) {
      String originalCode = orig.getCode();
      code = newCode;
      modified = !originalCode.equals(code);
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      Patch patch = (Patch) o;
      return isModified() == patch.isModified()
          && Objects.equals(getCode(), patch.getCode())
          && Objects.equals(getAddress(), patch.getAddress());
    }

    @Override
    public int hashCode() {
      return Objects.hash(getCode(), getAddress(), isModified());
    }
  }
}
