//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import anvill.ProgramSpecifier;

import java.io.FileOutputStream;

public class SpecifySingleFunction extends GhidraScript {

    public void run() throws Exception {
	var func =  this.currentProgram.getFunctionManager().getFunctionContaining(currentLocation.getAddress());
	var spec = ProgramSpecifier.specifySingleFunction(func);
	
	var file = askFile("Create output file" ,"Create");
        var strm = new FileOutputStream(file);
        spec.writeTo(strm);
    }

}