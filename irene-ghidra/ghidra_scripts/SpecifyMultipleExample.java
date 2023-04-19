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

public class SpecifyMultipleExample extends GhidraScript {

  public void run() throws Exception {

    var f1 = getFunctionAt(getAddressFactory().getAddress("00011c9c"));
    print(f1.toString());
    var f2 = getFunctionAt(getAddressFactory().getAddress("00011c5c"));
    print(f2.toString());
    var spec = ProgramSpecifier.specifyFunctions(this.currentProgram, Arrays.asList(f2, f1));

    var file = askFile("Create output file", "Create");
    var strm = new FileOutputStream(file);
    spec.writeTo(strm);
  }
}
