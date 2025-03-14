import anvill.ProgramSpecifier;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.*;
import java.io.FileOutputStream;
import java.nio.file.Path;
import java.util.Objects;

public class anvillHeadlessFunctionExport extends GhidraScript {
  public void run() throws Exception {
    var scr = this.getScriptArgs();
    var fname = Path.of(scr[0]).toFile();
    var func_name = scr[1];
    var target_func = this.getFunction(func_name);
    println("Looking for: " + func_name);

    for (var func : this.currentProgram.getFunctionManager().getFunctions(true)) {
      println("Has func by name: " + func.getName());
    }

    Objects.requireNonNull(target_func);

    var spec =
        ProgramSpecifier.specifySingleFunction(
            target_func, new scala.collection.immutable.HashSet<>());

    var strm = new FileOutputStream(fname);
    spec.writeTo(strm);
  }
}
