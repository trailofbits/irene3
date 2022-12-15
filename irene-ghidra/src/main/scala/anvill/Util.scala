package anvill

import ghidra.program.model.listing.Function
import ghidra.program.model.block.BasicBlockModel
import ghidra.util.task.TaskMonitor
import ghidra.program.model.address.Address

import java.{util => ju}
import scalax.collection.Graph
import scalax.collection.GraphEdge.DiEdge
import ghidra.program.model.block.CodeBlock
import collection.JavaConverters._
import ghidra.program.model.block.CodeBlockReference
import ghidra.program.model.block.CodeBlockIterator
import ghidra.program.model.block.CodeBlockReferenceIterator

import scala.collection.mutable.ListBuffer

object Util {
  type CFG = Graph[CodeBlock, DiEdge]

  def collectRefs(blk: CodeBlockReferenceIterator): List[CodeBlock] = {
    val buff: ListBuffer[CodeBlock] = ListBuffer()
    while (blk.hasNext()) {
      buff += blk.next().getDestinationBlock()
    }
    buff.toList
  }

  def blkToEdges(blk: CodeBlock): Seq[DiEdge[CodeBlock]] = {
    val child_blks =
      collectRefs(blk.getDestinations(TaskMonitor.DUMMY))
    child_blks.map(c => DiEdge((blk, c)))
  }

  def getCfgAsGraph(func: Function): CFG = {
    val model = BasicBlockModel(func.getProgram)
    val blks = model.getCodeBlocksContaining(func.getBody(), TaskMonitor.DUMMY)

    val edge_buff: ListBuffer[DiEdge[CodeBlock]] = ListBuffer()
    val nodes: ListBuffer[CodeBlock] = ListBuffer()

    while (blks.hasNext()) {
      val curr = blks.next()
      edge_buff.addAll(blkToEdges(curr))
      nodes += curr
    }

    Graph.from(nodes.toList, edge_buff.toList)
  }
}
