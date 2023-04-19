package anvill.plugin.anvillgraph;

import com.google.gson.*;
import java.util.*;

public class AnvillPatchInfo {

  public static final String PATCHES_FIELD_NAME = "patches";
  private final JsonObject jsonContent;

  private List<Patch> patches = new ArrayList<>();

  private final Gson gson;

  public AnvillPatchInfo(String jsonObject) throws InstantiationException {
    gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
    jsonContent = JsonParser.parseString(jsonObject).getAsJsonObject();

    for (JsonElement patchJson : selectJsonPatches()) {
      patches.add(Patch.parseJson(patchJson.getAsJsonObject()));
    }
  }

  public List<Patch> getPatches() {
    return patches;
  }

  private JsonArray selectJsonPatches() throws InstantiationException {
    JsonArray arr = jsonContent.getAsJsonArray(PATCHES_FIELD_NAME);
    if (arr == null) {
      throw new InstantiationException("Cannot find field '" + PATCHES_FIELD_NAME + "' in JSON");
    }
    return arr;
  }

  /**
   * Serialize only the changed patches
   *
   * @return JSON encoding of changed blocks
   */
  public String serialize() {
    JsonObject jRet = new JsonObject();
    JsonArray jPatches = new JsonArray();
    jRet.add(PATCHES_FIELD_NAME, jPatches);

    // Add changed patches only
    for (Patch p : patches) {
      if (p.isModified()) {
        jPatches.add(p.getJson());
      }
    }

    return gson.toJson(jRet);
  }

  public boolean isModified() {
    return patches.stream().anyMatch(Patch::isModified);
  }

  public static class Patch {

    public static final String ADDR_FIELD_NAME = "patch-addr";
    public static final String CODE_FIELD_NAME = "patch-code";
    private String code;
    private final String address;
    private final JsonObject orig;
    private boolean modified;

    Patch(String address, String code, JsonObject orig) {
      this.orig = orig;
      this.address = address;
      this.code = code;
      this.modified = false;
    }

    public static Patch parseJson(JsonObject object) throws InstantiationException {
      JsonElement addressObj = object.get(ADDR_FIELD_NAME);
      if (addressObj == null) {
        throw new InstantiationException("Cannot find " + ADDR_FIELD_NAME + " in JSON");
      }
      String address = addressObj.getAsString();
      JsonElement codeObj = object.get(CODE_FIELD_NAME);
      if (codeObj == null) {
        throw new InstantiationException("Cannot find " + CODE_FIELD_NAME + " in JSON");
      }
      String code = codeObj.getAsString();
      return new Patch(address, code, object);
    }

    /**
     * Create a new JSON object with potentially updated fields/values
     *
     * @return a new JSON object
     */
    public JsonObject getJson() {
      JsonObject jRet = orig.deepCopy();
      jRet.add(CODE_FIELD_NAME, new JsonPrimitive(code));
      return jRet;
    }

    public boolean isModified() {
      return modified;
    }

    public String getAddress() {
      return address;
    }

    public String getCode() {
      return code;
    }

    public void setCode(String newCode) {
      String originalCode = orig.get(CODE_FIELD_NAME).getAsString();
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
      return modified == patch.modified
          && Objects.equals(code, patch.code)
          && Objects.equals(address, patch.address)
          && Objects.equals(orig, patch.orig);
    }

    @Override
    public int hashCode() {
      return Objects.hash(code, address, orig, modified);
    }
  }
}
