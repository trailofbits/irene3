package anvill.plugin;

import java.io.File;

/** This class holds user input for lowering PatchLang code. */
public class PatchLowerInput {
  private String features;
  private String cpu;
  private String backend;

  private File origBin;

  private String detourLoc;

  private boolean shouldOptForSize;

  public PatchLowerInput(
      String features,
      String cpu,
      String backend,
      File origBin,
      String detour_loc,
      boolean shouldOptForSize) {
    this.features = features;
    this.cpu = cpu;
    this.backend = backend;
    this.origBin = origBin;
    this.detourLoc = detour_loc;
    this.shouldOptForSize = shouldOptForSize;
  }

  public boolean isShouldOptForSize() {
    return shouldOptForSize;
  }

  public void setShouldOptForSize(boolean shouldOptForSize) {
    this.shouldOptForSize = shouldOptForSize;
  }

  public File getOrigBin() {
    return origBin;
  }

  public void setOrigBin(File orig_bin) {
    this.origBin = orig_bin;
  }

  public String getDetourLoc() {
    return detourLoc;
  }

  public void setDetourLoc(String detourLoc) {
    this.detourLoc = detourLoc;
  }

  // Getters
  public String getFeatures() {
    return features;
  }

  public String getCpu() {
    return cpu;
  }

  public String getBackend() {
    return backend;
  }

  // Setters
  public void setFeatures(String features) {
    this.features = features;
  }

  public void setCpu(String cpu) {
    this.cpu = cpu;
  }

  public void setBackend(String backend) {
    this.backend = backend;
  }

  @Override
  public String toString() {
    return "PatchLowerInput{"
        + "features='"
        + features
        + '\''
        + ", cpu='"
        + cpu
        + '\''
        + ", backend='"
        + backend
        + '\''
        + '}';
  }
}
