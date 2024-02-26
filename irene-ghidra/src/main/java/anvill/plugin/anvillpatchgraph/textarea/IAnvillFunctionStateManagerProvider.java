package anvill.plugin.anvillpatchgraph.textarea;

import anvill.plugin.anvillpatchgraph.AnvillStateUpdateListener;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import java.util.List;
import java.util.Map;

public interface IAnvillFunctionStateManagerProvider {
  void setProgram(Program program);

  void setLocation(ProgramLocation loc);

  void dispose();

  Map<String, List<AnvillStateUpdateListener>> listeners();
}
