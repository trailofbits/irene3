/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *			http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// @category Analysis.PPC

import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.*;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashSet;

public class PropagatePPCConstantReferences extends GhidraScript {
  private String[] strRegSet = {"r2", "r13"};
  private String[] strLowSet = {"subi", "addi", "ori", "e_or2i", "e_add16i"};

  private HashSet<String> lowSet = new HashSet<String>(Arrays.asList(strLowSet));
  private HashSet<String> registerSet = new HashSet<String>(Arrays.asList(strRegSet));

  /**
   * Apply register context to all memory blocks that are executable
   *
   * @param regName register name
   * @param value context value
   */
  private void setRegisterContext(String regName, BigInteger value) {
    Register reg = currentProgram.getRegister(regName);
    for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
      if (block.isExecute()) {
        try {
          currentProgram.getProgramContext().setValue(reg, block.getStart(), block.getEnd(), value);
        } catch (ContextChangeException e) {
          throw new AssertException(e); // no instructions should exist yet
        }
      }
    }
  }

  @Override
  public void run() throws Exception {
    long numInstructions = currentProgram.getListing().getNumInstructions();
    monitor.initialize((int) (numInstructions));
    monitor.setMessage("Constant Propagation Markup");

    Memory mem = currentProgram.getMemory();
    MemoryBlock startup_section = mem.getBlock(".startup");

    AddressSet restrictedSet = new AddressSet(startup_section.getStart(), startup_section.getEnd());

    // iterate over all functions within the startup section
    FunctionIterator fiter = currentProgram.getFunctionManager().getFunctions(restrictedSet, true);
    while (fiter.hasNext()) {
      if (monitor.isCancelled()) {
        break;
      }

      // get the function body
      Function func = fiter.next();
      Address start = func.getEntryPoint();

      // follow all flows building up context
      // use context to fill out addresses on certain instructions
      // Use this to set the initial values for r2/r13 which contain
      // the address of SDA_BASE and SDA2_BASE
      ConstantPropagationContextEvaluator eval =
          new ConstantPropagationContextEvaluator(true) {

            @Override
            public boolean evaluateContext(VarnodeContext context, Instruction instr) {
              String mnemonic = instr.getMnemonicString();
              if (lowSet.contains(mnemonic)) {
                Register reg = instr.getRegister(0);
                if (reg != null) {
                  BigInteger val = context.getValue(reg, false);
                  if (val != null) {
                    long lval = val.longValue();
                    if (registerSet.contains(reg.toString())) {
                      printf("Setting %s to 0x%x\n", reg.toString(), lval);
                      setRegisterContext(reg.toString(), val);
                      registerSet.remove(reg.toString());
                    }
                  }
                }
              }
              return false;
            }
          };

      SymbolicPropogator symEval = new SymbolicPropogator(currentProgram);
      symEval.setParamRefCheck(true);
      symEval.setReturnRefCheck(true);
      symEval.setStoredRefCheck(true);

      symEval.flowConstants(start, func.getBody(), eval, true, monitor);
    }
  }
}
