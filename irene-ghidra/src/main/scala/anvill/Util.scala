package anvill

import ghidra.program.model.listing.Function
import ghidra.program.model.block.BasicBlockModel
import ghidra.util.task.TaskMonitor
import ghidra.program.model.address.Address
import scalax.collection.OuterEdge
import scalax.collection.io.dot.*
import implicits.*

import java.util as ju
import scalax.collection.immutable.Graph
import scalax.collection.edges.DiEdge
import ghidra.program.model.block.CodeBlock

import collection.JavaConverters.*
import ghidra.program.model.block.CodeBlockReference
import ghidra.program.model.block.CodeBlockIterator
import ghidra.program.model.block.CodeBlockReferenceIterator
import specification.specification.Register as RegSpec
import specification.specification.Value as ValueSpec
import specification.specification.Variable as VariableSpec
import specification.specification.TypeSpec

import scala.collection.mutable.ListBuffer
import ghidra.program.model.lang.Register
import ProgramSpecifier.{getRegisterName, specifyContextAssignments}
import specification.specification.TypeSpec.Type
import specification.specification.BaseType.BT_U8
import ghidra.util.Msg

import scala.collection.mutable.Buffer
import ghidra.util.task.TimeoutTaskMonitor

import java.util.concurrent.TimeUnit
import java.util.Objects
import ghidra.program.model.listing.Program
import ghidra.program.model.listing.Instruction
import specification.specification.CodeBlock as CodeBlockSpec
import ghidra.program.model.block.CodeBlockModel
import aQute.bnd.service.progress.ProgressPlugin.Task
import com.google.common.collect.{ImmutableRangeMap, Range, RangeMap}
import ghidra.framework.model.{DomainFile, DomainObject}
import ghidra.program.model.pcode.{PcodeOp, Varnode}
import ghidra.program.model.listing.Function as GFunction
import ghidra.program.model.symbol.{
  ExternalLocation,
  Namespace,
  Symbol,
  SymbolType
}
import ghidra.util.exception.{CancelledException, VersionException}

import java.io.IOException

object Util {

  def getBlockByAddr(
      blkMap: Map[Long, CodeBlockSpec],
      addr: Long
  ): Option[CodeBlockSpec] = {
    blkMap.find((_, blk) => blk.address == addr).map(_._2)
  }

  def getIncomingAddresses(func: Function, blk: CodeBlock): Seq[Address] = {
    getValidAddresses(
      func,
      blk.getSources(TaskMonitor.DUMMY),
      ref => ref.getSourceAddress
    )
  }

  def getOutgoingAddresses(func: Function, blk: CodeBlock): Seq[Address] = {
    getValidAddresses(
      func,
      blk.getDestinations(TaskMonitor.DUMMY),
      ref => ref.getDestinationAddress
    )
  }

  abstract class ProgramAnalysisUtilMixin {
    val prog: Program

    lazy val base_reg_map: RangeMap[Address, Register] = {
      val map_builder: ImmutableRangeMap.Builder[Address, Register] =
        ImmutableRangeMap.builder()
      this.prog.getLanguage
        .getRegisters()
        .asScala
        .filter(_.isBaseRegister)
        .foreach(base_reg => {
          // Calculate the address range for each base register.
          val base_reg_end_addr = base_reg.getAddress.add(base_reg.getNumBytes)
          map_builder.put(
            Range.closedOpen(base_reg.getAddress, base_reg_end_addr),
            base_reg
          )
        })
      map_builder.build()
    }

    def getInstruction(op: PcodeOp): Option[Instruction] =
      Option(prog.getListing.getInstructionAt(op.getSeqnum.getTarget))

    def getUniqueFlow(op: PcodeOp): Option[Address] = getInstruction(op)
      .flatMap(i => Option.when(i.getFlows.length == 1)(i.getFlows()(0)))

    def getUniqueCallTarget(op: PcodeOp): Option[GFunction] =
      getUniqueFlow(op).flatMap(fl =>
        Option(prog.getFunctionManager.getFunctionAt(fl))
      )

    def registerToDefinedVnode(reg: Register): Varnode = {
      val base = reg.getBaseRegister
      Varnode(base.getAddress, base.getNumBytes)
    }

    def vnodeToBaseRegNodeOrUnique(vnode: Varnode): Option[Varnode] =
      Option
        .when(vnode.isUnique)(vnode)
        .orElse(
          Option.when(vnode.isRegister)(
            registerToDefinedVnode(base_reg_map.get(vnode.getAddress))
          )
        )
  }

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

  type CFG = Graph[CodeBlock, DiEdge[CodeBlock]]

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
    child_blks.map(c => DiEdge(blk, c.getDestinationBlock()))
  }

  def getEdgeSet(cfg: CFG): Set[(Long, Long)] = {
    cfg.edges
      .map(e =>
        (
          e.source.getFirstStartAddress().getOffset(),
          e.target.getFirstStartAddress().getOffset()
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

  def renderCfg(cfg: ComputeNodeContext.CFG): String = {
    val root = DotRootGraph(directed = true, id = Some("CFG"))

    def edgeTransformer(
        edge: ComputeNodeContext.CFG#InnerEdge
    ): Option[(DotGraph, DotEdgeStmt)] = {
      val eo = edge.outer
      val label = eo.label
      Some(
        root,
        DotEdgeStmt(
          NodeId(eo.source.toString),
          NodeId(eo.target.toString),
          List(DotAttr(Id("label"), Id(label.toString)))
        )
      )
    }

    cfg.toDot(root, edgeTransformer)
  }

  def getLocalSymbolByName(
      program: Program,
      name: String
  ): Option[Symbol] = {
    program.getSymbolTable
      .getGlobalSymbols(name)
      .iterator()
      .asScala
      .nextOption()
  }

  def getExtSymbolByName(program: Program, name: String): Option[Symbol] = {
    program.getSymbolTable
      .getExternalSymbols(name)
      .iterator()
      .asScala
      .nextOption()
  }

  def getGotAddr(symbol: Symbol): Option[Address] = {
    symbol.getProgram.getRelocationTable.getRelocations.asScala
      .find(relocation => symbol.getName == relocation.getSymbolName)
      .map(relocation => relocation.getAddress)
  }

  def createLibraryProgram(
      libraryFile: DomainFile,
      monitor: TaskMonitor
  ): Option[Program] = {
    var libraryObject: DomainObject = null
    try {
      libraryObject = libraryFile.getImmutableDomainObject(
        this,
        DomainFile.DEFAULT_VERSION,
        monitor
      )
      if (!libraryObject.isInstanceOf[Program]) return None
    } catch {
      case e: VersionException =>
        Msg.showError(this, null, "Version Exception", e.getMessage)
        return None
      case e: IOException =>
        Msg.showError(this, null, "IO Exception", e.getMessage)
        return None
      case e: CancelledException =>
        monitor.cancel()
        return None
    }
    Some(libraryObject.asInstanceOf[Program])
  }

  def getLinkedExternalProgram(symbol: Symbol): Option[Program] =
    for {
      program <- Option(symbol.getProgram)
      externalLoc <- getExternalLocation(symbol)
      extLibrary <- Option(
        program.getExternalManager
          .getExternalLibrary(externalLoc.getLibraryName)
      )
      libPath <- Option(extLibrary.getAssociatedProgramPath)
      projectData <- Option(program.getDomainFile.getParent.getProjectData)
      libFile <- Some(projectData.getFile(libPath))
      extProg <- Util.createLibraryProgram(libFile, null)
    } yield extProg

  def getExternalLocation(symbol: Symbol): Option[ExternalLocation] = {
    Option.when(symbol.isExternal)(
      symbol.getProgram.getExternalManager.getExternalLocation(symbol)
    )
  }

  def getSymbolLibraryName(symbol: Symbol): Option[String] = {
    @annotation.tailrec
    def loop(ns: Namespace): Option[String] = {
      Option(ns) match {
        case Some(namespace) if namespace.isLibrary => Some(namespace.getName)
        case Some(namespace) => loop(namespace.getParentNamespace)
        case None            => None
      }
    }

    loop(symbol.getParentNamespace)
  }
}
