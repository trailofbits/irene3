package anvill.macho

import ghidra.program.model.listing.Program

object MachoDetection:

  def isMachO(prog: Program): Boolean =
    prog.getExecutableFormat.toLowerCase.contains("mach-o")
