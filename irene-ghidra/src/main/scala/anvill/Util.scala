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
import ghidra.util.Msg
import scala.collection.mutable.Buffer
import ghidra.util.task.TimeoutTaskMonitor
import java.util.concurrent.TimeUnit
import java.util.Objects
import ghidra.program.model.listing.Program
import ghidra.program.model.listing.Instruction
import specification.specification.{CodeBlock => CodeBlockSpec}
import anvill.ProgramSpecifier.specifyContextAssignments
import ghidra.program.model.block.CodeBlockModel
import aQute.bnd.service.progress.ProgressPlugin.Task

object Util {

  def sizeToArray(sz: Int): TypeSpec = {
    TypeSpec(
      Type.Array(
        TypeSpec.ArrayType(
          Some(TypeSpec(Type.Base(BT_U8))),
          sz
        )
      )
    )
  }

  def sizeToType(sz: Int): TypeSpec = {
    ProgramSpecifier.integerTypes
      .get((sz, false))
      .getOrElse(sizeToArray(sz))
  }

  // This isnt right... we need a better notion of variables, we want to create variables for live locations... but what's the type?
  // Really want the type of the live assignment
  def registerToType(reg: Register): TypeSpec = {
    sizeToType(reg.getNumBytes())
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
        isFuncAddr(func, ref.getDestinationAddress()) && isValidBlock(
          func.getProgram(),
          ref.getDestinationBlock()
        )
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

  def isFuncAddr(func: Function, addr: Address): Boolean = {
    val maybe_func = Option(
      func
        .getProgram()
        .getFunctionManager()
        .getFunctionContaining(addr)
    )

    !addr.isExternalAddress() && maybe_func
      .map(_ == func)
      .getOrElse(true)
  }

  def isFuncBlock(func: Function, blk: CodeBlock): Boolean = {
    isFuncAddr(func, blk.getFirstStartAddress())
  }

  // We depend on some assumptions about basic blocks
  // for now we rely on blocks being contigous non empty sequences of instructions
  def isValidBlock(program: Program, blk: CodeBlock): Boolean = {
    val blkinsns: ju.Iterator[Instruction] = program
      .getListing()
      .getInstructions(blk, true)
    val blkinsnsseq = blkinsns.asScala.toSeq

    !blkinsnsseq.isEmpty && blkinsnsseq.map(_.getLength()).sum.toLong == ((blk
      .getMaxAddress()
      .getOffset() - blk.getFirstStartAddress().getOffset()) + 1)
  }

  def getValidAddresses(
      func: Function,
      it: CodeBlockReferenceIterator,
      addr: CodeBlockReference => Address
  ): Seq[Address] = {
    collectRefs(it)
      .map(addr(_))
      .filter(Util.isFuncAddr(func, _))
  }

  def getReachableCodeBlocks(func: Function): Seq[CodeBlock] = {
    val res: Buffer[CodeBlock] = Buffer()
    val closed_list: scala.collection.mutable.Set[Long] =
      scala.collection.mutable.Set()
    val prog = func.getProgram()
    val listing = prog.getListing()
    val model = BasicBlockModel(prog)
    val queue = scala.collection.mutable.Queue[Address]()
    val monitor = TaskMonitor.DUMMY

    queue.enqueue(func.getEntryPoint())
    while (queue.size > 0) {
      val addr = queue.dequeue()

      if (!closed_list.contains(addr.getOffset())) {
        closed_list.add(addr.getOffset())
        val block = model.getCodeBlockAt(addr, monitor)

        if (
          Objects.nonNull(
            block
          ) && isValidBlock(func.getProgram(), block)
        ) {
          // If we arent going to consider this block then we may as well not consider its successors unless we encounter them somehow
          // on a different path
          queue ++= getValidAddresses(
            func,
            block.getSources(monitor),
            ref => ref.getSourceAddress()
          )

          queue ++= getValidAddresses(
            func,
            block.getDestinations(monitor),
            ref => ref.getDestinationAddress()
          )

          res += block

        } else {
          Msg.warn(this, s"Skipping invalid block: $addr")
        }
      }
    }
    res.toSeq
  }

  def getBodyCFG(func: Function): Iterator[CodeBlock] = {
    val model = BasicBlockModel(func.getProgram())
    val blks = model.getCodeBlocksContaining(func.getBody(), TaskMonitor.DUMMY)
    blks.iterator().asScala
  }

  def getCfgAsGraph(func: Function): CFG = {

    val edge_buff: ListBuffer[DiEdge[CodeBlock]] = ListBuffer()
    val nodes: ListBuffer[CodeBlock] = ListBuffer()
    getBodyCFG(func).foreach(curr => {
      edge_buff.addAll(blkToEdges(func, curr))
      nodes += curr
    })

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
