//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;

public class FixGlobalRegister extends GhidraScript {

  public void run() throws Exception {
    // exit if not analyzing expected powerpc architecture
    if (!this.currentProgram.getLanguageID().getIdAsString().equals("PowerPC:BE:64:VLE-32addr")) {
      return;
    }
    var listing =  this.currentProgram.getListing();
    var instrs = listing.getInstructions(true);
    List<String> globalRegNames = List.of("r2", "r13");
    var globalVals = new HashMap<Register, Long>();
    for (var instr : instrs) {
      switch (instr.getMnemonicString()) {
        case "e_lis":
        case "lis": {
          // get the first half of pointer
          var reg = instr.getRegister(0);
          if (globalRegNames.contains(reg.toString())) {
            globalVals.put(reg, instr.getScalar(1).getUnsignedValue() << 16);
          }
          break;
        }
        case "e_or2i":
        case "ori": {
          // get second half of pointer
          var reg = instr.getRegister(0);
          if (globalRegNames.contains(reg.toString())) {
            var pointer_part = Optional.ofNullable(globalVals.get(reg));
            if (pointer_part.isPresent()) {
              long upper_half = pointer_part.get();
              globalVals.put(reg, upper_half | instr.getScalar(instr.getNumOperands() - 1).getUnsignedValue());
            }
          }
          break;
        }
      }

      if (globalVals.size() > globalRegNames.size()) {
        break;
      }
    }

    var context = this.currentProgram.getProgramContext();
    var addressSpace = this.currentProgram.getAddressFactory().getDefaultAddressSpace();

    for (var entry : globalVals.entrySet()) {
      printf("Setting register %s to 0x%x\n", entry.getKey(), entry.getValue());
      var regVal = new RegisterValue(entry.getKey(), BigInteger.valueOf(entry.getValue()));
      context.setRegisterValue(addressSpace.getMinAddress(), addressSpace.getMaxAddress(), regVal);
    }

    AutoAnalysisManager analysisMgr = AutoAnalysisManager.getAnalysisManager(currentProgram);
    analysisMgr.scheduleOneTimeAnalysis(
        analysisMgr.getAnalyzer("PowerPC Constant Reference Analyzer"), currentProgram.getMemory());
  }
}
