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
import ghidra.program.model.data.TypeDef
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
import specification.specification.FunctionLinkage
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
import specification.specification.ReturnStackPointer
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
import specification.specification.Callable
import specification.specification.{CodeBlock => CodeBlockSpec}
import specification.specification.StackEffects
import specification.specification.Variables
import ghidra.program.model.data.GenericCallingConvention
import ghidra.program.model.lang.CompilerSpec
import ghidra.program.model.block.BasicBlockModel
import ghidra.program.model.block.CodeBlock
import ghidra.program.model.block.CodeBlockReference
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
import scala.collection.mutable.{Map => MutableMap}
import ghidra.program.model.address.Address
import ghidra.program.model.listing.ThunkFunction
import java.util.ResourceBundle.Control
import ghidra.program.model.lang.Register
import ghidra.util.Msg
import ghidra.program.model.symbol.Symbol
import ghidra.program.model.listing.Function
import ghidra.program.model.pcode.DataTypeSymbol
import ghidra.program.model.symbol.SymbolType
import ghidra.program.model.pcode.HighFunctionDBUtil
import org.python.modules.jffi.DynamicLibrary.DataSymbol
import ghidra.program.model.listing.FunctionSignature
import ghidra.program.model.pcode.FunctionPrototype
import ghidra.program.model.pcode.HighVariable
import ghidra.program.model.pcode.HighParam
import ghidra.program.model.pcode.HighSymbol
import specification.specification.Callsite
import java.util.Objects
import ghidra.program.model.data.AbstractStringDataType
import specification.specification.StackFrame
import ghidra.app.cmd.function.CallDepthChangeInfo
import ghidra.util.task.TaskMonitor

def pair[A, B](ma: Option[A], mb: Option[B]): Option[(A, B)] =
  ma.flatMap(a => mb.map(b => (a, b)))

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

  def getTypeSpecRecCall(
      repr_type: DataType,
      builder: Seq[TypeSpec] => TypeSpec,
      components: Seq[DataType],
      aliases: MutableMap[Long, TypeSpec]
  ): TypeSpec = {

    // TODO(Ian): this is hacky and we should just have a seen set or something that gets passed down and
    // checked if seen -> then return an alias spec, expecting that it will be built.
    aliases.put(
      repr_type.getUniversalID().getValue(),
      TypeSpec(TypeSpec.Type.Alias(repr_type.getUniversalID().getValue()))
    )

    val parent_spec = builder(
      components.map(d =>
        Option(d.getUniversalID())
          .map(id => TypeSpec(TypeSpec.Type.Alias(id.getValue())))
          .getOrElse(
            // otherwise we have to make the recursive call in a thunk
            default = {
              getTypeSpec(d, aliases).get
            }
          )
      )
    )
    aliases.put(
      repr_type.getUniversalID().getValue(),
      parent_spec
    )

    for (comp <- components) {
      getTypeSpec(comp, aliases)
    }

    parent_spec
  }

  def getTypeSpec(
      maybe_t: DataType,
      aliases: MutableMap[Long, TypeSpec]
  ): Option[TypeSpec] = {
    Option(maybe_t)
      .flatMap(t =>
        val t_id = Option(t.getUniversalID()).map(id => id.getValue())
        val spec = t_id
          .flatMap(id => aliases.get(id))
          .orElse(
            t match
              case _: VoidDataType => Some(TypeSpec(Type.Base(BT_VOID)))
              case _: Undefined => Some(TypeSpec(Type.Unknown(t.getLength())))
              case _: DefaultDataType =>
                Some(TypeSpec(Type.Unknown(t.getLength())))
              case itype: AbstractIntegerDataType =>
                integerTypes
                  .get((t.getLength(), itype.isSigned()))
                  .orElse(Some(TypeSpec(Type.Unknown(t.getLength()))))
              case _: AbstractFloatDataType =>
                floatTypes
                  .get(t.getLength())
                  .orElse(Some(TypeSpec(Type.Unknown(t.getLength()))))
              case ptr: Pointer => {
                val pointee = getTypeSpec(ptr.getDataType(), aliases)
                Some(
                  TypeSpec(
                    Type
                      .Pointer(TypeSpec.PointerType(pointee, /*const=*/ false))
                  )
                )
              }
              case tdef: TypeDef => getTypeSpec(tdef.getBaseDataType(), aliases)
              case arr: ghidra.program.model.data.Array => {
                val base = getTypeSpec(arr.getDataType(), aliases)
                Some(
                  TypeSpec(
                    Type.Array(TypeSpec.ArrayType(base, arr.getNumElements()))
                  )
                )
              }
              case struct: Structure => {
                Some(
                  getTypeSpecRecCall(
                    struct,
                    comp_specs =>
                      TypeSpec(Type.Struct(TypeSpec.StructType(comp_specs))),
                    struct.getComponents().toList.map(_.getDataType),
                    aliases
                  )
                )
              }
              case str: AbstractStringDataType => {
                Msg.debug(this, "has string");
                Some(
                  TypeSpec(
                    Type.Array(
                      TypeSpec.ArrayType(
                        Some(TypeSpec(Type.Base(BT_CHAR))),
                        str.getLength + 1
                      )
                    )
                  )
                )
              }
              case _ => Some(TypeSpec(Type.Unknown(t.getLength())))
          )
        pair(t_id, spec).foreach((id, s) => aliases.put(id, s))
        spec
      )
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

    if (
      !func.getProgram().getLanguage().getProcessor().toString().contains("x86")
    ) {
      return CALLING_CONVENTION_UNSPECIFIED;
    }

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

  def getCFG(func: Function): Map[Long, CodeBlockSpec] = {
    val res = MutableMap[Long, CodeBlockSpec]()
    val prog = func.getProgram()
    val listing = prog.getListing()
    val model = BasicBlockModel(prog)
    val queue = scala.collection.mutable.Queue[Address]()
    val monitor = () => TimeoutTaskMonitor.timeoutIn(5, TimeUnit.SECONDS)
    def is_internal(addr: Address) = func == listing.getFunctionContaining(addr)
    queue.enqueue(func.getEntryPoint())
    while (queue.size > 0) {
      val addr = queue.dequeue()
      try {
        val block = model.getCodeBlockAt(addr, monitor())
        if (!res.isDefinedAt(addr.getOffset())) {
          if (
            Objects.nonNull(
              block
            ) && isValidBlock(func.getProgram(), block)
          ) {

            // If we arent going to consider this block then we may as well not consider its successors unless we encounter them somehow
            // on a different path
            val incoming = scala.collection.mutable.ArrayBuffer[Long]()
            val incoming_it = block.getSources(monitor())
            while (incoming_it.hasNext()) {
              val ref = incoming_it.next()
              val source_block_addr = ref.getSourceAddress()
              if (is_internal(source_block_addr)) {
                incoming.addOne(source_block_addr.getOffset())
                queue.enqueue(source_block_addr)
              }
            }

            val outgoing = scala.collection.mutable.ArrayBuffer[Long]()
            val outgoing_it = block.getDestinations(monitor())
            while (outgoing_it.hasNext()) {
              val ref = outgoing_it.next()
              val dest_block_addr = ref.getDestinationAddress()
              if (is_internal(dest_block_addr)) {
                outgoing.addOne(dest_block_addr.getOffset())
                queue.enqueue(dest_block_addr)
              }
            }

            res += (addr.getOffset() -> CodeBlockSpec(
              addr.getOffset(),
              block.getName(),
              incoming.toSeq,
              outgoing.toSeq,
              // Blocks can technically allow non contigous regions, we filter out blocks we cant handle through isValidBlock
              (block.getMaxAddress.getOffset() - addr.getOffset()).toInt + 1,
              specifyContextAssignments(
                prog,
                addr
              )
            ))

          } else {
            Msg.warn(this, s"Skipping invalid block: $addr")
          }
        }
      } catch {
        case e: ghidra.util.exception.TimeoutException => {
          Msg.warn(this, s"Timed out getting block $addr")
        }
        case e: ghidra.util.exception.CancelledException => {
          Msg.warn(this, s"Time out lead to sources cancel on block $addr")
        }
      }
    }
    res.toMap
  }

  def getStackRegister(program: Program): String = {
    getRegisterName(program.getCompilerSpec().getStackPointer())
  }

  def getRegisterName(reg: Register): String = {
    reg.getName().toUpperCase()
  }

  def specifySingleValue(func: Function, vnode: Varnode): ValueSpec = {
    val program = func.getProgram()
    val cspec = program.getCompilerSpec()
    val addr = vnode.getAddress()
    val param_size = func.getStackFrame().getParameterSize()
    val innerValue: InnerValue = if (addr.isRegisterAddress()) {
      val reg = program.getRegister(addr, vnode.getSize())
      Reg(RegSpec(getRegisterName(reg)))
    } else if (addr.isStackAddress()) {
      Mem(
        MemSpec(
          Some(getStackRegister(program)),
          addr.getOffset()
        )
      )
    } else {
      // TODO(frabert): Handle memory params
      throw new RuntimeException(
        "Storage kinds for varnodes other than register and stack are not implemented yet"
      )
    }

    ValueSpec(innerValue)
  }

  def specifyStorage(
      var_storage: VariableStorage,
      func: Function
  ): Seq[ValueSpec] = {
    var_storage
      .getVarnodes()
      .toSeq
      .map(specifySingleValue(func, _))
  }

  def isVariableComposedOfHashVarnodes(tvar: Variable): Boolean =
    tvar.getVariableStorage().getVarnodes().forall(v => v.isHash())

  def specifyVariable(
      tvar: Variable,
      aliases: MutableMap[Long, TypeSpec]
  ): VariableSpec = {

    val type_spec = getTypeSpec(tvar.getDataType(), aliases);
    VariableSpec(
      specifyStorage(tvar.getVariableStorage(), tvar.getFunction()),
      type_spec
    )
  }

  def specifyParam(
      param: Parameter,
      aliases: MutableMap[Long, TypeSpec]
  ): ParamSpec = {
    ParamSpec(Some(param.getName()), Some(specifyVariable(param, aliases)))
  }

  val returnAddressRegisterOverrides =
    Map(("ARM", "lr"), ("AARCH64", "x30"), ("PowerPC", "lr"))

  def specifyDefaultReturnAddress(cspec: CompilerSpec): Option[ValueSpec] = {
    val procstr = cspec.getLanguage().getProcessor().toString()

    // TODO(Ian): use a trie
    for ((k, v) <- returnAddressRegisterOverrides) {
      if (procstr.contains(k)) {
        return Some(
          ValueSpec(
            Reg(RegSpec(getRegisterName(cspec.getLanguage().getRegister(v))))
          )
        )
      }
    }

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
      // NOTE(alex): Ghidra 10.1.5 doesn't have have return address information in the x86_64:gcc
      // cspec so we should explicitly check for it here. Subsequent releases will have this
      // information so we only need to perform this check if no return address is found.
      var langDesc = cspec.getLanguage.getLanguageDescription
      return if (
        langDesc.getProcessor.toString.equals(
          "x86"
        ) && langDesc.getSize == 64 &&
        cspec.getCompilerSpecDescription.getCompilerSpecName.equals("gcc")
      ) {
        val sp = getRegisterName(cspec.getStackPointer)
        Some(
          ValueSpec(
            Mem(
              MemSpec(Some(sp), 0)
            )
          )
        )
      } else None
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
          val sp = getRegisterName(cspec.getStackPointer())
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

  def specifyCallableFromFunction(
      func: Function,
      defaultRetAddr: Option[ValueSpec],
      aliases: MutableMap[Long, TypeSpec],
      params: Seq[ParamSpec],
      retValue: Option[VariableSpec]
  ): Callable = {

    // FIXME(frabert): For now, we ignore the possibility that users may have
    //  overridden the default return address
    val retAddr: Option[ValueSpec] = None

    Callable(
      retAddr.orElse(defaultRetAddr),
      params,
      retValue,
      func.hasVarArgs(),
      func.hasNoReturn(),
      getCallingConvention(func),
      None,
      Some(
        ReturnStackPointer(
          Some(RegSpec(getStackRegister(func.getProgram()))),
          Some(
            Option(func.getCallingConvention())
              .getOrElse(
                func
                  .getProgram()
                  .getLanguage()
                  .getDefaultCompilerSpec()
                  .getDefaultCallingConvention()
              )
              .getStackshift()
          )
        )
      )
    )
  }

  def getStackEffects(
      func: Function,
      aliases: MutableMap[Long, TypeSpec]
  ): StackEffects = {
    /*def alloc_points = LiveStackVariableLocations
      .getAllocationPoints(func)

    def free_points = LiveStackVariableLocations
      .getFreePoints(func)

    def missed_allocs = LiveStackVariableLocations
      .getVariablesMissingFromPoints(func, alloc_points)

    def missed_frees = LiveStackVariableLocations
      .getVariablesMissingFromPoints(func, free_points)

    StackEffects(
      alloc_points.map(kv =>
        (
          kv._1.getOffset(),
          Variables(kv._2.map(v => specifyVariable(v, aliases)).toSeq)
        )
      ),
      free_points.map(kv =>
        (
          kv._1.getOffset(),
          Variables(kv._2.map(v => specifyVariable(v, aliases)).toSeq)
        )
      ),
      missed_allocs.map(x => specifyVariable(x, aliases)).toSeq,
      missed_frees.map(x => specifyVariable(x, aliases)).toSeq
    )*/
    StackEffects()
  }

  def maxDepth(func: Function): Int = {
    val cdi = CallDepthChangeInfo(func, TaskMonitor.DUMMY)
    val func_insns: ju.Iterator[Instruction] = func.getProgram
      .getListing()
      .getInstructions(func.getBody(), true)

    func_insns.asScala
      .filter(insn =>
        BasicBlockContextProducer.validDepth(cdi.getDepth(insn.getAddress()))
      )
      .map(insn => {
        var init_depth = cdi.getDepth(insn.getAddress())

        val disp =
          (if (insn.getFlowType().isCall()) {

             val cc = insn
               .getReferencesFrom()
               .find(_.getReferenceType().isCall())
               .flatMap(r =>
                 Option(
                   func
                     .getProgram()
                     .getFunctionManager()
                     .getFunctionAt(r.getToAddress())
                 )
               )
               .flatMap(f => Option(f.getCallingConvention()))
               .getOrElse(
                 func
                   .getProgram()
                   .getCompilerSpec()
                   .getDefaultCallingConvention()
               )
             -cc.getStackshift()
           } else {
             0
           })
        init_depth + disp
      })
      .map(_.abs)
      .maxOption
      .getOrElse(0)
  }

  def specifyFunction(
      func: Function,
      defaultRetAddr: Option[ValueSpec],
      aliases: MutableMap[Long, TypeSpec],
      linkage: FunctionLinkage
  ): FuncSpec = {

    val params = func.getParameters().toSeq.map(x => specifyParam(x, aliases))
    val retValue =
      Option(func.getReturn()).map(x => specifyVariable(x, aliases))
    var cfg = if func.isExternal() then { Map.empty }
    else { getCFG(func) }

    if (!(cfg contains func.getEntryPoint().getOffset())) {
      cfg = Map.empty
    }
    val max_depth = maxDepth(func)
    val bb_context_prod = BasicBlockContextProducer(func, max_depth)
    FuncSpec(
      getThunkRedirection(func.getProgram(), func.getEntryPoint())
        .getOffset(),
      linkage,
      Some(
        specifyCallableFromFunction(
          func,
          defaultRetAddr,
          aliases,
          params,
          retValue
        )
      ),
      cfg,
      func
        .getLocalVariables()
        .toSeq
        // We assume that hashed varnodes are either covered by live register analysis
        // Or live stack location analysis
        .filter(x => !isVariableComposedOfHashVarnodes(x))
        .map(x => x.getName() -> specifyVariable(x, aliases))
        .toMap,
      cfg.map((addr, cb) => {
        val gaddr = func.getProgram
          .getAddressFactory()
          .getDefaultAddressSpace
          .getAddress(addr)
        (
          addr,
          bb_context_prod.getBlockContext(
            gaddr,
            func
              .getProgram()
              .getListing()
              .getInstructionBefore(gaddr.add(cb.size))
              .getAddress()
          )
        )
      }),
      Some(getStackEffects(func, aliases)),
      Some(
        StackFrame(
          func.getStackFrame.getFrameSize,
          func.getStackFrame.getReturnAddressOffset,
          func.getStackFrame.getParameterSize,
          max_depth
        )
      )
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
      // FIXME(frabert): Ghidra does not recognize the OS of the challanges apparently,
      //    or maybe I'm looking for the wrong strings
      OS_LINUX
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
    } else if (procName.indexOf("powerpc") >= 0) {
      ARCH_PPC
    } else {
      ARCH_UNSPECIFIED
    }
  }

  def getThunkRedirection(prog: Program, addr: Address): Address = {
    val funcmgr = prog.getFunctionManager()
    Option(funcmgr.getFunctionAt(addr))
      .map(func =>
        if (func.isThunk()) {
          func.getThunkedFunction(true).getEntryPoint()
        } else {
          func.getEntryPoint()
        }
      )
      .getOrElse(addr)
  }

  val required_context_regs = Map("TMode" -> "TMReg", "vle" -> "VLEReg")

  def specifyContextAssignments(
      prog: Program,
      addr: Address
  ): Map[String, Long] = {
    val context = prog.getProgramContext()
    required_context_regs
      .flatMap((ghidra_reg_name, context_reg_name) => {
        val reg = Option(prog.getRegister(ghidra_reg_name));
        reg
          .flatMap(reg => Option(context.getValue(reg, addr, false)))
          .map(reg_val => (context_reg_name, reg_val.longValue()))

      })
      .toMap
  }

  enum ControlFlowOverride {
    case SJump(jmp: Jump)
    case SCall(call: Call)
    // Not a structure return, spec return
    case SRet(ret: Return)
    case SOther(oth: Other)
  }

  def controlFlowOverridesForInstruction(
      inst: Instruction,
      is_next_insn: Address => Boolean,
      function_at_addr: Address => Option[
        ghidra.program.model.listing.Function
      ],
      get_thunk_redirection: Address => Address
  ): Option[ControlFlowOverride] = {
    val addr = inst.getAddress().getOffset()
    val flow = inst.getFlowType()
    val has_fallthrough = inst.hasFallthrough()
    val is_conditional = flow.isConditional()
    val is_terminal = flow.isTerminal()
    val references = inst.getReferencesFrom()
    val pcode = inst.getPcode().toSeq

    if (flow.isJump()) {
      if (
        inst.getFlows().length == 1 && function_at_addr(
          inst.getFlows()(0)
        ).isDefined
      ) {
        return Some(
          ControlFlowOverride.SCall(
            Call(
              addr,
              /*returnAddress=*/ if (has_fallthrough)
                Some(inst.getFallThrough().getOffset())
              else { None },
              /*isTailcall=*/ true,
              /*stop=*/ is_terminal,
              /*targetAddress=*/ references.headOption
                .map(x => x.getToAddress())
                .map(x => get_thunk_redirection(x).getOffset())
            )
          )
        )
      }

      val flows = inst.getFlows().toSeq
      if (!flows.isEmpty && flows.forall(is_next_insn)) {
        return None
      }

      return Some(
        ControlFlowOverride.SJump(
          Jump(
            addr,
            flows.map(x =>
              JumpTarget(
                x.getOffset()
              )
            ),
            is_terminal
          )
        )
      );
    }

    if (flow.isCall()) {
      if (has_fallthrough) {
        val fallthrough_addr = inst.getFallThrough().getOffset()
        return Some(
          ControlFlowOverride.SCall(
            Call(
              addr,
              /*returnAddress=*/ Some(fallthrough_addr),
              /*isTailcall=*/ false,
              /*stop=*/ is_terminal,
              /*targetAddress=*/ references.headOption
                .map(x => x.getToAddress())
                .map(x => get_thunk_redirection(x).getOffset())
            )
          )
        );

      } else {
        return Some(
          ControlFlowOverride.SCall(
            Call(
              addr,
              /*returnAddress=*/ None,
              /*isTailcall=*/ false,
              /*stop=*/ is_terminal,
              /*targetAddress=*/ references.headOption
                .map(x => x.getToAddress())
                .map(x => get_thunk_redirection(x).getOffset())
            )
          )
        );
      }
      break
    }

    if (flow.isTerminal()) {
      if (inst.getPcode().toSeq.last.getOpcode() == PcodeOp.RETURN) {
        return Some(ControlFlowOverride.SRet(Return(addr, true)));
      } else {
        return Some(ControlFlowOverride.SOther(Other(addr, true)));
      }
    }
    None
  }

  def specifyControlFlow(prog: Program): ControlFlowOverrides = {
    val listing = prog.getListing()
    val inst_iterator: ju.Iterator[Instruction] = listing.getInstructions(true)
    val instructions = inst_iterator.asScala.toSeq
    val jumps = ListBuffer[Jump]()
    val calls = ListBuffer[Call]()
    val rets = ListBuffer[Return]()
    val other = ListBuffer[Other]()
    val refmgr = prog.getReferenceManager()

    for (inst <- instructions) {
      controlFlowOverridesForInstruction(
        inst,
        addr =>
          Option(inst.getFallThrough())
            .map(next_insn => next_insn == addr)
            .getOrElse(false),
        addr => Option(prog.getFunctionManager().getFunctionAt(addr)),
        getThunkRedirection(prog, _)
      ).foreach(over =>
        over match {
          case ControlFlowOverride.SRet(ret) => rets.addOne(ret)
          case ControlFlowOverride.SOther(other_elem) =>
            other.addOne(other_elem)
          case ControlFlowOverride.SJump(jmp)  => jumps.addOne(jmp)
          case ControlFlowOverride.SCall(call) => calls.addOne(call)
        }
      )
    }

    ControlFlowOverrides(jumps.toSeq, calls.toSeq, rets.toSeq, other.toSeq)
  }

  def gvOverrideType(
      dt: DataType,
      aliases: MutableMap[Long, TypeSpec]
  ): Option[TypeSpec] = {
    if (dt.isInstanceOf[Pointer]) {
      getTypeSpec(
        AbstractIntegerDataType.getSignedDataType(
          dt.getLength(),
          dt.getDataTypeManager()
        ),
        aliases
      )
    } else {
      None
    }
  }

  def specifyGlobalVariable(
      symbol: Symbol,
      aliases: MutableMap[Long, TypeSpec]
  ): Option[GlobalVariable] = {
    val program = symbol.getProgram()
    val listing = program.getListing()
    val addr = symbol.getAddress()
    Option(listing.getDataAt(addr))
      .flatMap(data => Option(data.getDataType()))
      .map(datatype =>
        GlobalVariable(
          getTypeSpec(datatype, aliases),
          addr.getOffset()
        )
      )
  }

  def specifyFunctionOrDecl(
      func: Function,
      defaultRetAddr: Option[ValueSpec],
      aliases: MutableMap[Long, TypeSpec],
      as_decl: Boolean
  ): FuncSpec = {
    val linkage = (as_decl, func.isExternal()) match {
      case (_, true) => FunctionLinkage.FUNCTION_LINKAGE_EXTERNAL
      case (true, _) =>
        FunctionLinkage.FUNCTION_LINKAGE_DECL
      case _ => FunctionLinkage.FUNCTION_LINKAGE_NORMAL_UNSPECIFIED
    }

    var spec = specifyFunction(func, defaultRetAddr, aliases, linkage)

    spec
  }

  def applyThunkRedirections(
      prog: Program,
      funcs: Seq[Function]
  ): Set[Function] = {
    funcs
      .map(x => getThunkRedirection(x.getProgram(), x.getEntryPoint()))
      .flatMap(x => Option(prog.getFunctionManager().getFunctionAt(x)))
      .toSet
  }

  def getGlobalsFromFunction(func: Function): Iterator[Symbol] = {
    val func_insns: ju.Iterator[Instruction] = func.getProgram
      .getListing()
      .getInstructions(func.getBody(), true)
    val prog = func.getProgram
    func_insns.asScala
      .flatMap(x => x.getReferencesFrom())
      .filter(ref => ref.getReferenceType().isData())
      .flatMap(data_ref => Option(prog.getSymbolTable().getSymbol(data_ref)))

  }

  def getOverrideForInsn(insn: Instruction): Option[DataTypeSymbol] = {
    insn
      .getSymbols()
      .filter(sym => {
        sym
          .getSymbolType() == SymbolType.LABEL
      })
      .flatMap(symb => Option(HighFunctionDBUtil.readOverride(symb)))
      .headOption

  }

  def overrideToCallable(
      called_function: Function,
      dsm: DataTypeSymbol,
      default_return_addr: Option[ValueSpec],
      aliases: MutableMap[Long, TypeSpec]
  ): Callable = {
    val sig = dsm.getDataType.asInstanceOf[FunctionSignature]
    Objects.requireNonNull(called_function)
    val types = Array(sig.getReturnType()) ++ sig
      .getArguments()
      .map(param => param.getDataType())
    val maybe_proto = Option(
      called_function
        .getProgram()
        .getCompilerSpec()
        .getCallingConvention(
          sig.getGenericCallingConvention().getDeclarationName()
        )
    )

    val proto = maybe_proto.getOrElse(
      called_function
        .getProgram()
        .getCompilerSpec()
        .getDefaultCallingConvention()
    )

    val locs =
      proto.getStorageLocations(called_function.getProgram(), types, false)

    val ret_storage = locs(0)
    val ret_type = types(0)

    val ret =
      Some(
        VariableSpec(
          specifyStorage(ret_storage, called_function),
          getTypeSpec(ret_type, aliases)
        )
      )

    val param_storage = locs.drop(1)

    val params =
      sig
        .getArguments()
        .zip(param_storage)
        .map((param_def, storage) =>
          ParamSpec(
            Option(param_def.getName()),
            Some(
              VariableSpec(
                specifyStorage(storage, called_function),
                getTypeSpec(param_def.getDataType(), aliases)
              )
            )
          )
        )
        .toIndexedSeq

    specifyCallableFromFunction(
      called_function,
      default_return_addr,
      aliases,
      params,
      ret
    )
  }

  // only allows one override per insn
  def getOverridesCallsitesForFunction(
      func: Function
  ): Map[Instruction, DataTypeSymbol] = {
    val func_insns: ju.Iterator[Instruction] = func.getProgram
      .getListing()
      .getInstructions(func.getBody(), true)

    func_insns.asScala
      .flatMap(insn => getOverrideForInsn(insn).map(over => (insn, over)))
      .toMap
  }

  def specifyCallsite(
      insn: Instruction,
      dsm: DataTypeSymbol,
      default_return_addr: Option[ValueSpec],
      aliases: MutableMap[Long, TypeSpec]
  ): Option[Callsite] = {
    val prog = insn.getProgram()

    val target_func = insn
      .getReferencesFrom()
      .filter(ref => ref.getReferenceType().isCall())
      .flatMap(ref =>
        Option(prog.getFunctionManager().getFunctionAt(ref.getToAddress()))
      )
      .headOption

    if (target_func.isEmpty) {
      return None
    }

    Option(prog.getFunctionManager().getFunctionContaining(insn.getAddress()))
      .map(containing_function =>
        Callsite(
          insn.getAddress().getOffset(),
          containing_function.getEntryPoint().getOffset(),
          Some(
            overrideToCallable(
              target_func.get,
              dsm,
              default_return_addr,
              aliases
            )
          )
        )
      )
  }

  def specifyProgram(
      prog: Program,
      function_def_list: Seq[Function],
      function_decl_list: Seq[Function]
  ): Specification = {
    val aliases = MutableMap[Long, TypeSpec]()
    val arch = getProgramArch(prog)
    val os = getProgramOS(prog)
    val listing = prog.getListing()
    val memory = prog.getMemory()
    val funcmgr = prog.getFunctionManager()
    val defaultRetAddr = specifyDefaultReturnAddress(prog.getCompilerSpec())

    val func_defs_redirected = applyThunkRedirections(prog, function_def_list)
    val func_decls_redirected =
      applyThunkRedirections(prog, function_decl_list) -- func_defs_redirected

    val func_specs = (func_decls_redirected.toSeq.map(
      specifyFunctionOrDecl(_, defaultRetAddr, aliases, true)
    ) ++ func_defs_redirected.toSeq.map(
      specifyFunctionOrDecl(_, defaultRetAddr, aliases, false)
    )).toList

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
      .filter(block =>
        !MemoryBlock.isExternalBlockAddress(block.getStart(), prog)
      )
      .filter(block => block.isLoaded())
      // Ignore blocks that are both empty and not writeable, since they would be useless anyway
      .filter(block => block.isWrite() || block.getSize() > 0)
      .map(specifyMemoryBlock)
    val global_specs = {
      func_defs_redirected
        .flatMap(getGlobalsFromFunction)
        .flatMap(x => specifyGlobalVariable(x, aliases))
    }

    val callsite_overrides =
      func_defs_redirected.toSeq
        .flatMap(getOverridesCallsitesForFunction)
        .flatMap((insn, dsm) =>
          specifyCallsite(insn, dsm, defaultRetAddr, aliases)
        )

    Specification(
      arch,
      os,
      func_specs,
      callsite_overrides,
      global_specs.toArray.toSeq,
      symbol_specs.toArray.toSeq,
      mem_specs.toArray.toSeq,
      Some(specifyControlFlow(prog)),
      aliases.view.toMap
    )
  }

  def calledFunctions(func: Function): Set[Function] = {
    val func_insns: ju.Iterator[Instruction] = func.getProgram
      .getListing()
      .getInstructions(func.getBody(), true)
    val prog = func.getProgram
    func_insns.asScala
      .flatMap(x => x.getReferencesFrom())
      .filter(ref => ref.getReferenceType().isCall())
      .flatMap(call_ref =>
        Option(prog.getFunctionManager().getFunctionAt(call_ref.getToAddress()))
      )
      .toSet
  }

  def specifySingleFunction(func: Function) = {
    val decls = calledFunctions(func)
    specifyProgram(func.getProgram(), List(func), decls.toSeq)
  }

  def specifyFunctions(
      program: Program,
      funcs: java.lang.Iterable[Function]
  ): Specification = {
    val func_col = funcs.iterator().asScala.toSeq
    val decls = func_col.flatMap(calledFunctions)
    specifyProgram(program, func_col, decls)
  }

  def specifyProgram(prog: Program): Specification = {
    val it: ju.Iterator[Function] = prog.getFunctionManager().getFunctions(true)
    specifyProgram(prog, it.asScala.toSeq, Seq.empty)
  }
}
