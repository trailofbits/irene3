package anvill

import ghidra.app.services.{AbstractAnalyzer, AnalysisPriority, AnalyzerType}
import ghidra.app.util.importer.MessageLog
import ghidra.framework.plugintool.PluginTool
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghidra.framework.cmd.BackgroundCommand
import ghidra.framework.model.DomainObject
import ghidra.program.model.block.BasicBlockModel
import ghidra.program.model.listing.Function as GFunction
import scala.jdk.CollectionConverters.IterableHasAsScala

class PrologEpilogueBackground(f: GFunction) extends BackgroundCommand:

  override def applyTo(
      domainObject: DomainObject,
      taskMonitor: TaskMonitor
  ): Boolean =
    val blkseq = Util.getBodyCFG(f).toList
    val decomp_c = BasicBlockSplit.getGhidraDecompilation(f)
    val exits = blkseq
      .filter(_.getFirstStartAddress == f.getEntryPoint)
      .flatMap(blk =>
        decomp_c.flatMap(decomp_c =>
          BasicBlockSplit.getPrologueExitAddr(
            blk,
            BasicBlockSplit.computeDecompilationMappings(decomp_c, blk)
          )
        )
      )
    val epilogue_entries = blkseq
      .filter(blk => Util.getOutgoingAddresses(f, blk).isEmpty)
      .flatMap(blk => {
        decomp_c.flatMap(decomp_c =>
          BasicBlockSplit.getEpilogueEntryAddr(
            blk,
            BasicBlockSplit.computeDecompilationMappings(decomp_c, blk)
          )
        )
      })

    (exits ++ epilogue_entries).foreach(addr =>
      SplitsManager(f.getProgram).addSplitForAddress(f.getEntryPoint, addr)
    )
    true

end PrologEpilogueBackground

class PrologueEpilogueAnalyzer
    extends AbstractAnalyzer(
      "Prologue/Epilogue Analyzer",
      "Heuristically determines " +
        "the extent of the prologue and epilouge in blocks",
      AnalyzerType.FUNCTION_ANALYZER
    ) {
  setPriority(AnalysisPriority.CODE_ANALYSIS.after().after())
  this.setSupportsOneTimeAnalysis()

  val SPLITS_MAP = "IRENE_SPLITS"

  override def added(
      program: Program,
      addressSetView: AddressSetView,
      taskMonitor: TaskMonitor,
      messageLog: MessageLog
  ): Boolean = {
    program.getFunctionManager
      .getFunctions(addressSetView, true)
      .asScala
      .foreach(f => {
        PrologEpilogueBackground(f).applyTo(program, taskMonitor)
      })
    true
  }
}
