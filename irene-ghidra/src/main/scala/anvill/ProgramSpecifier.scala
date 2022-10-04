package anvill;

import java.{util => ju}
import collection.JavaConverters._
import com.google.protobuf.ByteString
import ghidra.program.model.data.DataType
import ghidra.program.model.data.VoidDataType
import ghidra.program.model.data.Undefined
import ghidra.program.model.data.DefaultDataType
import ghidra.program.model.data.AbstractIntegerDataType
import ghidra.program.model.data.AbstractFloatDataType
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.TypedefDataType
import ghidra.program.model.data.Structure
import ghidra.program.model.data.DataTypeComponent
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.listing.Parameter
import ghidra.program.model.mem.Memory
import ghidra.program.model.mem.MemoryBlock
import ghidra.program.model.symbol.Symbol
import ghidra.program.model.symbol.SymbolType.GLOBAL_VAR
import scalaz._
import Scalaz._
import specification.specification.{Function => FuncSpec}
import specification.specification.{Memory => MemSpec}
import specification.specification.{Parameter => ParamSpec}
import specification.specification.{Value => ValueSpec}
import specification.specification.{Variable => VariableSpec}
import specification.specification.MemoryRange
import specification.specification.Specification
import specification.specification.{Symbol => SymbolSpec}
import specification.specification.GlobalVariable
import specification.specification.Value.InnerValue
import specification.specification.Value.InnerValue.Reg
import specification.specification.Value.InnerValue.Mem
import specification.specification.BaseType._
import specification.specification.TypeSpec
import specification.specification.TypeSpec.Type
import specification.specification.{Register => RegSpec}
import specification.specification.ControlFlowOverrides
import specification.specification.Jump
import specification.specification.JumpTarget
import specification.specification.Call
import specification.specification.Return
import specification.specification.Other
import specification.specification.CallingConvention._
import specification.specification.OS
import specification.specification.OS._
import specification.specification.Arch
import specification.specification.Arch._
import specification.specification.CallingConvention
import ghidra.program.model.data.GenericCallingConvention
import ghidra.program.model.lang.CompilerSpec
import ghidra.program.model.block.SimpleBlockModel
import ghidra.util.task.TimeoutTaskMonitor
import java.util.concurrent.TimeUnit
import ghidra.program.model.listing.Instruction
import scala.collection.mutable.ListBuffer
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.symbol.RefType
import ghidra.program.model.lang.BasicCompilerSpec
import javax.xml.parsers.DocumentBuilderFactory
import org.xml.sax.InputSource
import java.io.StringReader
import org.w3c.dom.Element
import org.w3c.dom.Node
import scala.util.control.Breaks._
import com.fasterxml.jackson.databind.introspect.TypeResolutionContext.Basic
import ghidra.program.model.listing.Variable
import ghidra.program.model.listing.Variable
import ghidra.program.model.listing.VariableStorage
import ghidra.program.model.pcode.Varnode

object ProgramSpecifier {
  val integerTypes = Map(
    (1, false) -> TypeSpec(Type.Base(BT_U8)),
    (1, true) -> TypeSpec(Type.Base(BT_I8)),
    (2, false) -> TypeSpec(Type.Base(BT_U16)),
    (2, true) -> TypeSpec(Type.Base(BT_I16)),
    (3, false) -> TypeSpec(Type.Base(BT_U24)),
    (3, true) -> TypeSpec(Type.Base(BT_I24)),
    (4, false) -> TypeSpec(Type.Base(BT_U32)),
    (4, true) -> TypeSpec(Type.Base(BT_I32)),
    (8, false) -> TypeSpec(Type.Base(BT_U64)),
    (8, true) -> TypeSpec(Type.Base(BT_I64)),
    (16, false) -> TypeSpec(Type.Base(BT_U128)),
    (16, true) -> TypeSpec(Type.Base(BT_I128))
  )
  val floatTypes = Map(
    2 -> TypeSpec(Type.Base(BT_FL16)),
    4 -> TypeSpec(Type.Base(BT_FL32)),
    8 -> TypeSpec(Type.Base(BT_FL64)),
    10 -> TypeSpec(Type.Base(BT_FL80)),
    12 -> TypeSpec(Type.Base(BT_FL96)),
    16 -> TypeSpec(Type.Base(BT_FL128))
  )

  def getTypeSpec(t: DataType): Option[TypeSpec] = {
    t match
      case _: VoidDataType    => Some(TypeSpec(Type.Base(BT_VOID)))
      case _: Undefined       => Some(TypeSpec(Type.Unknown(t.getLength())))
      case _: DefaultDataType => Some(TypeSpec(Type.Unknown(t.getLength())))
      case itype: AbstractIntegerDataType if itype.isSigned() =>
        integerTypes.get((t.getLength(), itype.isSigned()))
      case _: AbstractFloatDataType => floatTypes.get(t.getLength())
      case ptr: Pointer => {
        val pointee = getTypeSpec(ptr.getDataType());
        Some(
          TypeSpec(
            Type.Pointer(TypeSpec.PointerType(pointee, /*const=*/ false))
          )
        )
      }
      case tdef: TypedefDataType => getTypeSpec(tdef.getBaseDataType())
      case arr: ghidra.program.model.data.Array => {
        val base = getTypeSpec(arr.getDataType());
        Some(
          TypeSpec(Type.Array(TypeSpec.ArrayType(base, arr.getNumElements())))
        )
      }
      case struct: Structure =>
        struct
          .getComponents()
          .toList
          .map(x => x.getDataType)
          .map(getTypeSpec)
          .sequence
          .map(x => TypeSpec(Type.Struct(TypeSpec.StructType(x))))
      case _ => None
  }

  def specifyMemoryBlock(block: MemoryBlock): MemoryRange = {
    var data = ByteString.readFrom(block.getData())
    if (data.size() < block.getSize()) {
      val bytes: Array[Byte] = Array.fill(block.getSize().toInt)(0)
      data.copyTo(bytes, 0)
      data = ByteString.copyFrom(bytes)
    }
    MemoryRange(
      block.getStart().getOffset(),
      block.isWrite(),
      block.isExecute(),
      data
    )
  }

  def getCallingConvention(func: Function): CallingConvention = {
    val conv = func.getCallingConvention()
    if (conv == null) {
      CALLING_CONVENTION_UNSPECIFIED
    } else {
      conv.getGenericCallingConvention() match {
        case GenericCallingConvention.cdecl    => CALLING_CONVENTION_CDECL
        case GenericCallingConvention.fastcall => CALLING_CONVENTION_FASTCALL
        case GenericCallingConvention.stdcall  => CALLING_CONVENTION_STDCALL
        case GenericCallingConvention.thiscall => CALLING_CONVENTION_THISCALL
        case GenericCallingConvention.vectorcall =>
          CALLING_CONVENTION_VECTORCALL
        case _ => CALLING_CONVENTION_UNSPECIFIED
      }
    }
  }

  def specifySingleValue(program: Program, vnode: Varnode): ValueSpec = {
    val cspec = program.getCompilerSpec()
    val addr = vnode.getAddress()
    val innerValue: InnerValue = if (addr.isRegisterAddress()) {
      val reg = program.getRegister(addr, vnode.getSize())
      Reg(RegSpec(reg.getName()))
    } else if (addr.isStackAddress()) {
      Mem(MemSpec(Some(cspec.getStackPointer().getName()), addr.getOffset()))
    } else {
      // TODO(frabert): Handle memory params
      throw new RuntimeException(
        "Storage kinds for varnodes other than register and stack are not implemented yet"
      )
    }

    ValueSpec(innerValue)
  }

  def specifyStorage(var_storage: VariableStorage): Seq[ValueSpec] = {
    var_storage
      .getVarnodes()
      .toSeq
      .map(specifySingleValue(var_storage.getProgram(), _))
  }

  def specifyVariable(tvar: Variable): VariableSpec = {
    val type_spec = getTypeSpec(tvar.getDataType());
    VariableSpec(specifyStorage(tvar.getVariableStorage()), type_spec)
  }

  def specifyParam(param: Parameter): ParamSpec = {
    ParamSpec(Some(param.getName()), Some(specifyVariable(param)))
  }

  def specifyDefaultReturnAddress(cspec: CompilerSpec): Option[ValueSpec] = {
    // TODO(frabert): All of this should be deleted / redone as soon as we hear back from
    //                https://github.com/NationalSecurityAgency/ghidra/issues/4611
    if (!cspec.isInstanceOf[BasicCompilerSpec]) {
      return None
    }

    val basicCspec = cspec.asInstanceOf[BasicCompilerSpec]
    val factory = DocumentBuilderFactory.newInstance()
    val builder = factory.newDocumentBuilder()
    val is = InputSource(new StringReader(basicCspec.getXMLString()))
    val doc = builder.parse(is).getDocumentElement()
    doc.normalize()
    val nodes = doc.getChildNodes()
    val nodelist = doc.getElementsByTagName("returnaddress")
    if (nodelist.getLength() == 0) {
      return None
    }

    // The cast to Element should always succeed.
    // If the first node is not an Element (maybe text?) then the spec is malformed anyway
    val retaddrChildren = nodelist.item(0).asInstanceOf[Element].getChildNodes()
    for (i <- 0 until retaddrChildren.getLength()) {
      val valNode = retaddrChildren.item(i)
      if (valNode.getNodeType() == Node.ELEMENT_NODE) {
        val valElem = valNode.asInstanceOf[Element]
        val valName = valElem.getNodeName()
        if (valName.equals("register")) {
          return Some(ValueSpec(Reg(RegSpec(valElem.getAttribute("name")))))
        } else if (
          valName
            .equals("varnode") && valElem.getAttribute("space").equals("stack")
        ) {
          val sp = cspec.getStackPointer().getName()
          val offsetStringRaw = valElem.getAttribute("offset")
          val (offsetString, base) =
            if offsetStringRaw.startsWith("0x") then
              (offsetStringRaw.substring(2), 16)
            else (offsetStringRaw, 10)
          return Some(
            ValueSpec(
              Mem(
                MemSpec(Some(sp), java.lang.Long.parseLong(offsetString, base))
              )
            )
          )
        }
      }
    }

    None
  }

  def specifyFunction(
      func: Function,
      defaultRetAddr: Option[ValueSpec]
  ): FuncSpec = {
    val params = func.getParameters().toSeq.map(specifyParam)
    val retValue = Option(func.getReturn()).map(specifyVariable)

    // FIXME(frabert): For now, we ignore the possibility that users may have
    //  overridden the default return address
    val retAddr: Option[ValueSpec] = None

    FuncSpec(
      func.getEntryPoint().getOffset(),
      retAddr.orElse(defaultRetAddr),
      params,
      retValue,
      func.hasVarArgs(),
      func.hasNoReturn(),
      getCallingConvention(func)
    )
  }

  def getProgramOS(prog: Program): OS = {
    val format = prog.getExecutableFormat().toLowerCase();
    if (format.indexOf("mac os") >= 0) {
      OS_MACOS
    } else if (format.indexOf("win") >= 0) {
      OS_WINDOWS
    } else if (format.indexOf("solaris") >= 0) {
      OS_SOLARIS
    } else if (format.indexOf("linux") >= 0) {
      OS_LINUX
    } else {
      OS_UNSPECIFIED
    }
  }

  def getProgramArch(prog: Program): Arch = {
    val lang = prog.getLanguage()
    val processor = lang.getProcessor()
    val procName = processor.toString().toLowerCase()
    if (procName.indexOf("aarch64") >= 0) {
      ARCH_AARCH64
    } else if (procName.indexOf("arm") >= 0) {
      ARCH_AARCH32
    } else if (procName.indexOf("x86") >= 0) {
      if (lang.toString().indexOf("32") >= 0) {
        ARCH_X86
      } else {
        ARCH_AMD64
      }
    } else if (procName.indexOf("sparc") >= 0) {
      if (lang.toString().indexOf("32") >= 0) {
        ARCH_SPARC32
      } else {
        ARCH_SPARC64
      }
    } else {
      ARCH_UNSPECIFIED
    }
  }

  def specifyControlFlow(prog: Program): ControlFlowOverrides = {
    val listing = prog.getListing()
    val inst_iterator: ju.Iterator[Instruction] = listing.getInstructions(true)
    val instructions = inst_iterator.asScala.toSeq
    val jumps = ListBuffer[Jump]()
    val calls = ListBuffer[Call]()
    val rets = ListBuffer[Return]()
    val other = ListBuffer[Other]()

    for (inst <- instructions) {
      val addr = inst.getAddress().getOffset()
      val flow = inst.getFlowType()
      val has_fallthrough = inst.hasFallthrough()
      val is_conditional = flow.isConditional()
      val is_terminal = flow.isTerminal()
      if (flow.isJump()) {
        val flows = inst.getFlows().toSeq

        val unique_func =
          if flows.size == 1 then
            Option(prog.getFunctionManager().getFunctionAt(flows(0)))
          else None

        unique_func match {
          // Tail call
          case Some(_) => calls.addOne(Call(addr, None, true, true))
          case _ =>
            jumps.addOne(
              Jump(addr, flows.map(x => JumpTarget(x.getOffset())), is_terminal)
            )
        }
      }

      if (flow.isCall()) {
        if (has_fallthrough) {
          val fallthrough_addr = inst.getFallThrough().getOffset()
          val next_addr = inst.getNext().getAddress().getOffset()
          calls.addOne(
            Call(
              addr,
              /*returnAddress=*/ Some(fallthrough_addr),
              /*isTailcall=*/ false,
              /*stop=*/ is_terminal
            )
          )
        } else {
          calls.addOne(
            Call(
              addr,
              /*returnAddress=*/ None,
              /*isTailcall=*/ false,
              /*stop=*/ is_terminal
            )
          )
        }
      }

      if (flow.isTerminal()) {
        if (inst.getPcode().toSeq.last.getOpcode() == PcodeOp.RETURN) {
          rets.addOne(Return(addr, true))
        } else {
          other.addOne(Other(addr, true))
        }
      }
    }

    ControlFlowOverrides(jumps.toSeq, calls.toSeq, rets.toSeq, other.toSeq)
  }

  def specifyGlobalVariable(symbol: Symbol): Option[GlobalVariable] = {
    val program = symbol.getProgram()
    val listing = program.getListing()
    val addr = symbol.getAddress()
    val ty = listing.getDataAt(addr).getDataType()
    if (ty == null) {
      return None
    }

    Some(
      GlobalVariable(
        getTypeSpec(ty),
        addr.getOffset()
      )
    )
  }

  def specifyProgram(prog: Program): Specification = {
    val arch = getProgramArch(prog)
    val os = getProgramOS(prog)
    val listing = prog.getListing()
    val memory = prog.getMemory()

    val func_iterator: ju.Iterator[Function] =
      prog.getFunctionManager().getFunctions(true)
    val defaultRetAddr = specifyDefaultReturnAddress(prog.getCompilerSpec())
    val func_specs =
      func_iterator.asScala.toSeq.map(func =>
        specifyFunction(func, defaultRetAddr)
      )

    val symbol_specs = {
      val sym_iterator: ju.Iterator[Symbol] =
        prog.getSymbolTable().getAllSymbols(false);
      sym_iterator.asScala.toSeq.map(x =>
        SymbolSpec(x.getName(), x.getAddress().getOffset())
      )
    }
    val mem_specs = memory
      .getBlocks()
      .toSeq
      .filter(block => block.isLoaded())
      // Ignore blocks that are both empty and not writeable, since they would be useless anyway
      .filter(block => block.isWrite() || block.getSize() > 0)
      .map(specifyMemoryBlock)
    val global_specs = {
      val sym_iterator: ju.Iterator[Symbol] =
        prog.getSymbolTable().getAllSymbols(false);
      sym_iterator.asScala.toSeq
        .filter(x => {
          // Exclude symbols to executable data
          val block = memory.getBlock(x.getAddress())
          block != null && !block.isExecute()
        })
        .filter(x => {
          // Exclude non-global and external symbols
          val ns = x.getParentNamespace()
          ns.isGlobal() && !ns.isExternal()
        })
        .filter(symbol => {
          // Exclude symbols with no references
          val references = symbol.getReferences().toSeq
          references.exists(ref => {
            ref.getReferenceType() != RefType.EXTERNAL_REF
          })
        })
        .flatMap(specifyGlobalVariable)
    }
    Specification(
      arch,
      os,
      func_specs,
      global_specs,
      symbol_specs,
      mem_specs,
      Some(specifyControlFlow(prog))
    )
  }
}
