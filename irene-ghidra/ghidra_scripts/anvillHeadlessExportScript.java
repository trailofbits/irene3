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
import java.util.Arrays;
import java.nio.file.Path;

public class anvillHeadlessExportScript extends GhidraScript {
	public void run() throws Exception {
		var scr = this.getScriptArgs();
		var fname = Path.of(scr[0]).toFile();

		var spec = ProgramSpecifier.specifyProgram(this.currentProgram);

		var strm = new FileOutputStream(fname);
		spec.writeTo(strm);
	}
}
