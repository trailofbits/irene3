package compiler;

import anvill.plugin.PatchLowerInput;
import ghidra.util.Msg;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Optional;

public class PatchCompiler {
  private final CommandLineDriver driver;
  private final File wdir;

  public PatchCompiler(CommandLineDriver driver) throws IOException {
    this.driver = driver;
    this.wdir = Files.createTempDirectory("irene-decomp").toFile();
    Msg.info(this, this.wdir.toString());
  }

  private Path getWdirPath(String fname) {
    return Path.of(this.wdir.getAbsolutePath(), fname);
  }

  public File getWdir() {
    return wdir;
  }

  void writeModule(String moduletxt) throws IOException {
    var patchlang_mod = this.getWdirPath("module.irene");
    var fw = new BufferedWriter(new FileWriter(patchlang_mod.toFile()));
    fw.write(moduletxt);
    fw.close();
  }

  public void compileModule(String moduletxt, long uid, PatchLowerInput plinput) {
    try {
      writeModule(moduletxt);
    } catch (IOException e) {
      throw new RuntimeException(
          "Failed to write module: " + this.getWdirPath("module.irene") + ":\n" + moduletxt, e);
    }

    this.driver.setWdir(Path.of(this.wdir.getAbsolutePath()));
    var source_orig_bin = plinput.getOrigBin().toPath();
    var target_orig_bin = this.getWdirPath("orig_bin");
    try {
      Files.copy(source_orig_bin, target_orig_bin);
    } catch (IOException e) {
      throw new RuntimeException(
          "Failed to copy orig bin '" + source_orig_bin + "' to '" + target_orig_bin + "'", e);
    }

    var patchlang_mod = this.getWdirPath("module.irene");
    var patchir_mod = this.getWdirPath("module.mlir");
    var patchir_mod_err = this.getWdirPath("module.mlir.stderr.log");
    try {
      this.driver.runCommand(
          new String[] {"irene3-patchlang2patchir"},
          Optional.of(patchlang_mod.toFile()),
          Optional.of(patchir_mod.toFile()),
          Optional.of(patchir_mod_err.toFile()));
    } catch (CommandLineDriverException e) {
      Msg.showError(
          this,
          null,
          "Docker container running irene3-patchlang2patchir failed",
          "See '"
              + patchir_mod_err
              + "' for log output. If you have not saved output results, the file may no longer exist.",
          e);
      return;
    }

    var assembly_file = this.getWdirPath("patch.S");
    var metadata = this.getWdirPath("patch.json");
    var assembly_file_log = this.getWdirPath("patch.stdout.log");
    var assembly_file_stderr = this.getWdirPath("patch.stderr.log");
    try {
      this.driver.runCommand(
          new String[] {
            "irene3-patchir-compiler",
            "-region_uid",
            Long.toString(uid),
            "-cpu",
            plinput.getCpu(),
            "-features",
            plinput.getFeatures(),
            "-backend",
            plinput.getBackend(),
            "-patch_def",
            patchir_mod.toString(),
            "-json_metadata",
            metadata.toString(),
            "-out",
            assembly_file.toString(),
            "-opt_space",
            plinput.isShouldOptForSize() ? "true" : "false"
          },
          Optional.empty(),
          Optional.of(assembly_file_log.toFile()),
          Optional.of(assembly_file_stderr.toFile()));
    } catch (CommandLineDriverException e) {
      Msg.showError(
          this,
          null,
          "Docker container running irene3-patchir-compiler failed",
          "See '"
              + assembly_file_log
              + "' and '"
              + assembly_file_stderr
              + "' for log output. If you have not saved output results, the file may no longer exist.",
          e);
      return;
    }

    var tmp_ouput_bin = this.getWdirPath("outbin");
    var assembler_log = this.getWdirPath("assembler.stdout.log");
    var assembler_stderr = this.getWdirPath("assembler.stderr.log");
    try {
      ArrayList<String> command =
          new ArrayList<>(
              Arrays.asList(
                  "python3",
                  "-m",
                  "patch_assembler.assembler",
                  "--in_assembly",
                  assembly_file.toString(),
                  "--metadata",
                  metadata.toString(),
                  "--output",
                  tmp_ouput_bin.toString()));
      if (!plinput.getDetourLoc().isEmpty()) {
        command.add("--detour_pos");
        command.add(plinput.getDetourLoc());
      }
      command.add(target_orig_bin.toString());
      String[] comm_array = new String[command.size()];
      comm_array = command.toArray(comm_array);

      this.driver.runCommand(
          comm_array,
          Optional.empty(),
          Optional.of(assembler_log.toFile()),
          Optional.of(assembler_stderr.toFile()));
    } catch (CommandLineDriverException e) {
      Msg.showError(
          this,
          null,
          "Docker container running python patch_assembler.assembler failed",
          "See '"
              + assembler_log
              + "' and '"
              + assembler_stderr
              + "' for log output. Once you close this dialog, the file may no longer exist, so please move it somewhere permanent if you would like to keep it around.",
          e);
      return;
    }
  }

  public void dispose() {
    this.wdir.delete();
  }
}
