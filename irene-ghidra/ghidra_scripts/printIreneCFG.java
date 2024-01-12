import anvill.ComputeNodeContext;
import anvill.Util;
import ghidra.app.script.GhidraScript;
import java.io.FileWriter;

public class printIreneCFG extends GhidraScript {
  @Override
  protected void run() throws Exception {
    var func =
        this.currentProgram
            .getFunctionManager()
            .getFunctionContaining(this.currentLocation.getAddress());
    var str = Util.renderCfg(ComputeNodeContext.func_to_cfg(func));
    var fl = this.askFile("Save to file", "Save");
    var wrtr = new FileWriter(fl);
    wrtr.write(str);
    wrtr.close();
  }
}
