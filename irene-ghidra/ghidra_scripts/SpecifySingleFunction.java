// TODO write a description for this script
// @author
// @category _NEW_
// @keybinding
// @menupath
// @toolbar

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
import java.util.Arrays;
import scalapb.json4s.JsonFormat;

public class SpecifySingleFunction extends GhidraScript {

  private String PROTOBUF_CHOICE = "Protobuf";
  private String JSON_CHOICE = "JSON";

  public void run() throws Exception {
    var func =
        this.currentProgram
            .getFunctionManager()
            .getFunctionContaining(currentLocation.getAddress());
    var spec =
        ProgramSpecifier.specifySingleFunction(func, new scala.collection.immutable.HashSet<>());

    var format =
        askChoice(
            "Choose output format",
            "Choose an output format to export as",
            Arrays.asList(PROTOBUF_CHOICE, JSON_CHOICE),
            PROTOBUF_CHOICE);
    if (format == null) {
      return;
    }

    var file = askFile("Create output file", "Create");
    var strm = new FileOutputStream(file);

    if (format.equals(PROTOBUF_CHOICE)) {
      spec.writeTo(strm);
    } else {
      assert (format.equals(JSON_CHOICE));
      var json = JsonFormat.toJsonString(spec);
      strm.write(json.getBytes());
    }
  }
}
