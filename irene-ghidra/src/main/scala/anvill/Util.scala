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
import specification.specification.{Register => RegSpec}
import specification.specification.{Value => ValueSpec}
import specification.specification.{Variable => VariableSpec}
import specification.specification.TypeSpec

import scala.collection.mutable.ListBuffer
import ghidra.program.model.lang.Register
import ProgramSpecifier.getRegisterName

object Util {

  // This isnt right... we need a better notion of variables, we want to create variables for live locations... but what's the type?
  // Really want the type of the live assignment
  def registerToType(reg: Register): Option[TypeSpec] = {
    ProgramSpecifier.integerTypes.get((reg.getNumBytes(), false))
  }

  def registerToVariable(reg: Register): VariableSpec = {
    val valspec = ValueSpec(
      ValueSpec.InnerValue.Reg(RegSpec(getRegisterName(reg)))
    )

    val typespec = registerToType(reg)

    if (typespec.isEmpty) {
      throw new IllegalStateException(
        "A register should be convertable to a sized type"
      )
    }

    VariableSpec(Seq(valspec), typespec)
  }

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
