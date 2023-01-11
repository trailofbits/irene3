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
import specification.specification.TypeSpec.Type
import specification.specification.BaseType.BT_U8
object Util {

  // This isnt right... we need a better notion of variables, we want to create variables for live locations... but what's the type?
  // Really want the type of the live assignment
  def registerToType(reg: Register): TypeSpec = {
    ProgramSpecifier.integerTypes
      .get((reg.getNumBytes(), false))
      .getOrElse(
        TypeSpec(
          Type.Array(
            TypeSpec.ArrayType(
              Some(TypeSpec(Type.Base(BT_U8))),
              reg.getNumBytes()
            )
          )
        )
      )
  }

  def registerToVariable(reg: Register): VariableSpec = {
    val valspec = ValueSpec(
      ValueSpec.InnerValue.Reg(RegSpec(getRegisterName(reg)))
    )

    val typespec = registerToType(reg)

    VariableSpec(Seq(valspec), Some(typespec))
  }

  type CFG = Graph[CodeBlock, DiEdge]

  def collectRefs(blk: CodeBlockReferenceIterator): List[CodeBlockReference] = {
    val buff: ListBuffer[CodeBlockReference] = ListBuffer()
    while (blk.hasNext()) {
      buff += blk.next()
    }
    buff.toList
  }

  def blkToEdges(func: Function, blk: CodeBlock): Seq[DiEdge[CodeBlock]] = {
    val child_blks =
      collectRefs(blk.getDestinations(TaskMonitor.DUMMY)).filter(ref =>
        func.getBody().contains(ref.getDestinationAddress())
      )
    child_blks.map(c => DiEdge((blk, c.getDestinationBlock())))
  }

  def getEdgeSet(cfg: CFG): Set[(Long, Long)] = {
    cfg.edges
      .map(e =>
        (
          e.source.toOuter.getFirstStartAddress().getOffset(),
          e.target.toOuter.getFirstStartAddress().getOffset()
        )
      )
      .toSet
  }
  def getCfgAsGraph(func: Function): CFG = {
    val model = BasicBlockModel(func.getProgram)
    val blks = model.getCodeBlocksContaining(func.getBody(), TaskMonitor.DUMMY)

    val edge_buff: ListBuffer[DiEdge[CodeBlock]] = ListBuffer()
    val nodes: ListBuffer[CodeBlock] = ListBuffer()

    while (blks.hasNext()) {
      val curr = blks.next()
      edge_buff.addAll(blkToEdges(func, curr))
      nodes += curr
    }

    Graph.from(nodes.toList, edge_buff.toList)
  }

  def getLiveRegisters(
      ps: Set[specification.specification.Parameter]
  ): Set[specification.specification.Register] = {

    ps.flatMap(p =>
      p.reprVar
        .map(v => v.values.flatMap(v => v.innerValue.reg))
        .getOrElse(Seq.empty)
    )
  }

}
