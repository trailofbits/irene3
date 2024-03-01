package anvill;

import java.security as js
import java.util as ju
import com.google.protobuf.ByteString
import ghidra.program.model.data.{
  AbstractFloatDataType,
  AbstractIntegerDataType,
  AbstractStringDataType,
  Composite,
  DataType,
  DataTypeComponent,
  DefaultDataType,
  FunctionDefinition,
  GenericCallingConvention,
  Pointer,
  Structure,
  TypeDef,
  Undefined,
  Union,
  VoidDataType
}
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.listing.Parameter
import ghidra.program.model.mem.Memory
import ghidra.program.model.mem.MemoryBlock
import ghidra.program.model.symbol.{
  ExternalLocation,
  RefType,
  Symbol,
  SymbolType
}
import scalaz.*
import Scalaz.*
import specification.specification.{
  Arch,
  Call,
  Callable,
  CallingConvention,
  Callsite,
  ControlFlowOverrides,
  FunctionLinkage,
  GlobalVariable,
  Jump,
  JumpTarget,
  MemoryRange,
  OS,
  Other,
  ProgramAddress,
  RelativeAddress,
  Return,
  ReturnStackPointer,
  Specification,
  StackEffects,
  StackFrame,
  TypeHint,
  TypeSpec,
  Variables,
  BlockContext as BlockContextSpec,
  CodeBlock as CodeBlockSpec,
  Function as FuncSpec,
  Memory as MemSpec,
  Parameter as ParamSpec,
  Register as RegSpec,
  Symbol as SymbolSpec,
  Value as ValueSpec,
  Variable as VariableSpec
}
import specification.specification.Value.InnerValue
import specification.specification.Value.InnerValue.Reg
import specification.specification.Value.InnerValue.Mem
import specification.specification.BaseType.*
import specification.specification.TypeSpec.Type
import specification.specification.CallingConvention.*
import specification.specification.OS.*
import specification.specification.Arch.*
import ghidra.program.model.lang.CompilerSpec
import ghidra.program.model.block.BasicBlockModel
import ghidra.program.model.block.CodeBlock
import ghidra.program.model.block.CodeBlockReference
import ghidra.util.task.TimeoutTaskMonitor

import java.util.concurrent.TimeUnit
import ghidra.program.model.listing.Instruction

import scala.collection.mutable.ListBuffer
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.lang.BasicCompilerSpec

import javax.xml.parsers.DocumentBuilderFactory
import org.xml.sax.InputSource

import java.io.{IOException, StringReader}
import org.w3c.dom.Element
import org.w3c.dom.Node

import scala.util.control.Breaks.*
import com.fasterxml.jackson.databind.introspect.TypeResolutionContext.Basic
import ghidra.program.model.listing.Variable
import ghidra.program.model.listing.Variable
import ghidra.program.model.listing.VariableStorage
import ghidra.program.model.pcode.Varnode

import scala.collection.mutable.Map as MutableMap
import ghidra.program.model.address.Address
import ghidra.program.model.listing.ThunkFunction

import java.util.ResourceBundle.Control
import ghidra.program.model.lang.Register
import ghidra.util.{Msg, UniversalID}
import ghidra.program.model.symbol.Symbol
import ghidra.program.model.listing.Function
import ghidra.program.model.pcode.DataTypeSymbol
import ghidra.program.model.pcode.HighFunctionDBUtil
import org.python.modules.jffi.DynamicLibrary.DataSymbol
import ghidra.program.model.listing.FunctionSignature
import ghidra.program.model.pcode.FunctionPrototype
import ghidra.program.model.pcode.HighVariable
import ghidra.program.model.pcode.HighParam
import ghidra.program.model.pcode.HighSymbol

import java.util.Objects
import ghidra.app.cmd.function.CallDepthChangeInfo
import ghidra.util.task.TaskMonitor

import scala.collection.mutable.Map as MutableMap
import scala.collection.mutable.Set as MutableSet
import scala.collection.immutable.SortedMap
import anvill.Util.{
  getExtSymbolByName,
  getExternalLocation,
  getGotAddr,
  getLinkedExternalProgram,
  getLocalSymbolByName,
  getReachableCodeBlocks,
  getSymbolLibraryName
}
import ghidra.framework.model.{DomainFile, DomainObject}
import ghidra.program.database.external.ExternalManagerDB
import ghidra.program.model.address.AddressSet
import ghidra.program.model.pcode.VarnodeTranslator
import ghidra.program.model.pcode.SequenceNumber
import ghidra.util.exception.{CancelledException, VersionException}

import java.util.concurrent.atomic.AtomicLong
import scala.jdk.CollectionConverters.*
import scala.math.abs

def pair[A, B](ma: Option[A], mb: Option[B]): Option[(A, B)] =
  ma.flatMap(a => mb.map(b => (a, b)))

object ProgramSpecifier {

  /** Generate new Uid */
  object createNewUid extends (() => Long) {
    var nextUid: AtomicLong = AtomicLong(1);

    def apply: Long = {
      nextUid.getAndIncrement()
    }
  }

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

  // Takes a collection of compoenents to be passed to
  // a composite type buidler. Non-typespec components are evaluated to
  // TypeSpecs before calling the builder.
  // Right(TypeSpec) allows the caller to fill in type specs when they are
  // already known.
  def getTypeSpecRecCall(
      repr_type: DataType,
      builder: Seq[TypeSpec] => TypeSpec,
      components: Seq[Either[DataType, TypeSpec]],
      aliases: MutableMap[Long, TypeSpec]
  ): TypeSpec = {

    // TODO(Ian): this is hacky and we should just have a seen set or something that gets passed down and
    // checked if seen -> then return an alias spec, expecting that it will be built.
    aliases.put(
      repr_type.getUniversalID().getValue(),
      TypeSpec(TypeSpec.Type.Alias(repr_type.getUniversalID().getValue()))
    )

    val parent_spec = builder(
      components.map {
        case Left(d) =>
          Option(d.getUniversalID())
            .flatMap(id =>
              Option.when(aliases.contains(id.getValue()))(
                TypeSpec(TypeSpec.Type.Alias(id.getValue()))
              )
            )
            .getOrElse(
              // otherwise we have to make the recursive call in a thunk
              default = {
                getTypeSpec(d, aliases).get
              }
            )
        case Right(sp) => sp
      }
    )
    aliases.put(
      repr_type.getUniversalID().getValue(),
      parent_spec
    )

    for (comp <- components) {
      Msg.info(this, s"Going for cmp $comp")
      comp.left.foreach(getTypeSpec(_, aliases))
    }

    TypeSpec(Type.Alias(repr_type.getUniversalID.getValue))
  }

  def getTypeSpec(
      maybe_t: DataType,
      aliases: MutableMap[Long, TypeSpec]
  ): Option[TypeSpec] = {
    Msg.info(this, s"Looking at ty: $maybe_t")
    Option(maybe_t)
      .flatMap(t =>
        val t_id = Option(t.getUniversalID).map(id => id.getValue)
        // Even if we've built the type we want to refer to the type by name so we refer to the alias
        // Named types are built once, we could really probably get rid of the alias map and only have a named type map
        val spec = t_id
          .flatMap(l => Option.when(aliases.contains(l))(l))
          .flatMap(l => Some(TypeSpec(Type.Alias(l))))
          .orElse(
            t match
              case _: VoidDataType       => Some(TypeSpec(Type.Base(BT_VOID)))
              case _: FunctionDefinition => Some(TypeSpec(Type.Base(BT_VOID)))
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
              case tdef: TypeDef => {
                val tdefspec = getTypeSpec(tdef.getBaseDataType(), aliases)
                tdefspec.foreach(aliases.put(tdef.getUniversalID.getValue, _))
                tdefspec
              }
              case arr: ghidra.program.model.data.Array => {
                val base = getTypeSpec(arr.getDataType(), aliases)
                Some(
                  TypeSpec(
                    Type.Array(TypeSpec.ArrayType(base, arr.getNumElements()))
                  )
                )
              }
              case struct: Structure => {
                Msg.info(this, s"Looking at struct: $struct}")
                // Creates padding of the given size in bytes that can be passed to the builder
                val get_pad: Int => Either[DataType, TypeSpec] = num => {
                  val base = Some(TypeSpec(Type.Base(BT_U8)))
                  Right(TypeSpec(Type.Array(TypeSpec.ArrayType(base, num))))
                }
                // The end padding is the difference between the last byte of the
                // last field and the established lengh of the structure.
                val end_padding =
                  struct.getLength - struct.getComponents.toList.lastOption
                    .map(c => c.getOffset + c.getLength)
                    .getOrElse(0)
                val epad_ty =
                  if end_padding > 0 then Some(get_pad(end_padding)) else None
                Some(
                  getTypeSpecRecCall(
                    struct,
                    comp_specs =>
                      // Adds every field as a data type to the component list
                      // if the next elem exists, and is not adjacent to the end of the current field
                      // we add an array of padding to make the padding bytes explicit.
                      TypeSpec(Type.Struct(TypeSpec.StructType(comp_specs))),
                    (struct.getComponents.toList
                      .sliding(2, 1)
                      .flatMap(c => {
                        val felem = c.head
                        val selem = c.lift(1)
                        List(Left(felem.getDataType)) ++ selem.flatMap(s => {
                          val padding =
                            s.getOffset - (felem.getOffset + felem.getLength)
                          if padding > 0 then Some(get_pad(padding)) else None
                        })
                      }) ++ struct.getComponents.toList.lastOption
                      .map(c => Left(c.getDataType)) ++ epad_ty).toSeq,
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
              case union: Union => {
                val base = Some(TypeSpec(Type.Base(BT_U8)))
                val ty = TypeSpec(
                  Type.Struct(
                    TypeSpec.StructType(
                      Seq(
                        TypeSpec(
                          Type.Array(TypeSpec.ArrayType(base, union.getLength))
                        )
                      )
                    )
                  )
                )
                val l = union.getUniversalID.getValue()
                aliases.put(l, ty)
                Some(TypeSpec(Type.Alias(l)))
              }
              case _ => {
                // if length is negative, the type has no size
                if (t.getLength() < 0) {
                  Some(TypeSpec(Type.Base(BT_VOID)))
                } else {
                  Some(TypeSpec(Type.Unknown(t.getLength())))
                }
              }
          )

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
      conv.getName match {
        case CompilerSpec.CALLING_CONVENTION_cdecl => CALLING_CONVENTION_CDECL
        case CompilerSpec.CALLING_CONVENTION_fastcall =>
          CALLING_CONVENTION_FASTCALL
        case CompilerSpec.CALLING_CONVENTION_stdcall =>
          CALLING_CONVENTION_STDCALL
        case CompilerSpec.CALLING_CONVENTION_thiscall =>
          CALLING_CONVENTION_THISCALL
        case CompilerSpec.CALLING_CONVENTION_vectorcall =>
          CALLING_CONVENTION_VECTORCALL
        case _ => CALLING_CONVENTION_UNSPECIFIED
      }
    }
  }

  def getStackRegister(program: Program): Register = {
    program.getCompilerSpec().getStackPointer()
  }

  def getStackRegisterName(program: Program): String = {
    getRegisterName(getStackRegister(program))
  }

  def getRegisterName(reg: Register): String = {
    reg.getName().toUpperCase()
  }

  def specifySingleValue(program: Program, vnode: Varnode): ValueSpec = {
    val cspec = program.getCompilerSpec()
    val addr = vnode.getAddress()
    val innerValue: InnerValue = if (addr.isRegisterAddress()) {
      val reg = program.getRegister(addr, vnode.getSize())
      Reg(RegSpec(getRegisterName(reg), Some(vnode.getSize())))
    } else if (addr.isStackAddress()) {
      Mem(
        MemSpec(
          Some(getStackRegisterName(program)),
          addr.getOffset(),
          vnode.getSize()
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
      .map(specifySingleValue(func.getProgram(), _))
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
    Map(("ARM", "lr"), ("AARCH64", "x30"), ("PowerPC", "lr"), ("Sparc", "o7"))

  def specifyDefaultReturnAddress(program: Program): Option[ValueSpec] = {
    val cspec = program.getCompilerSpec()
    val procstr = cspec.getLanguage().getProcessor().toString()

    // TODO(Ian): use a trie
    for ((k, v) <- returnAddressRegisterOverrides) {
      if (procstr.contains(k))
        return Some(
          ValueSpec(
            Reg(
              RegSpec(getRegisterName(cspec.getLanguage().getRegister(v)))
            )
          )
        )
    }

    val raddr = cspec.getDefaultCallingConvention().getReturnAddress()
    if (raddr.length == 1) {
      val rvnode = raddr(0)
      return Some(specifySingleValue(program, rvnode))
    }

    Msg.error(this, s"No return address location found for: $procstr")

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
          Some(RegSpec(getStackRegisterName(func.getProgram()))),
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

  def maxDepth(func: Function, cdi: CallDepthChangeInfo): Int = {
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

  def specifyBlock(func: Function, blk: CodeBlock): CodeBlockSpec = {
    val addr = blk.getFirstStartAddress()
    CodeBlockSpec(
      addr.getOffset(),
      blk.getName(),
      Util
        .getValidAddresses(
          func,
          blk.getSources(TaskMonitor.DUMMY),
          ref => ref.getSourceAddress()
        )
        .map(_.getOffset()),
      Util
        .getValidAddresses(
          func,
          blk.getDestinations(TaskMonitor.DUMMY),
          ref => ref.getDestinationAddress()
        )
        .map(_.getOffset()),
      (blk.getMaxAddress.getOffset() - addr.getOffset()).toInt + 1,
      specifyContextAssignments(func.getProgram(), addr),
      0
    )
  }

  def getCFG(
      func: Function,
      func_split_addrs: Set[Address] = Set.empty
  ): Map[Long, CodeBlockSpec] = {
    val body_cfg = Util.getBodyCFG(func)
    BasicBlockSplit.splitBlocksWithPrologueEpiloguePoints(
      func,
      body_cfg,
      func_split_addrs
    )
  }

  def getInScopeVars(
      prog: Program,
      cfg: Map[Long, BlockContextSpec]
  ): Set[ParamSpec] = {
    val in_scope: Set[ParamSpec] =
      cfg.flatMap((_, bspec) => bspec.liveAtEntries ++ bspec.liveAtExits).toSet
    in_scope.foreach(p => Msg.info(ProgramSpecifier, p.name))

    in_scope
  }

  def outputRegAssignersForInstruction(insn: Instruction): Seq[PcodeOp] =
    val out_regs =
      insn.getResultObjects.collect({ case x: Register => x }).toSet
    val seen_set: collection.mutable.Set[Register] = collection.mutable.Set()
    val unique_set: collection.mutable.Set[Register] = collection.mutable.Set()
    for (x <- insn.getPcode()) {
      if (Option(x.getOutput).isDefined && x.getOutput.isRegister) {
        val reg = insn.getProgram.getRegister(x.getOutput)
        if (seen_set.contains(reg)) {
          unique_set.remove(reg)
        } else {
          unique_set.add(reg)
          seen_set.add(reg)
        }
      }
    }

    insn
      .getPcode()
      .toSeq
      .filter(pc => {
        Option(pc.getOutput)
          .map(insn.getProgram.getRegister(_))
          .exists(r => out_regs.contains(r) && unique_set.contains(r))
      })

  def insnHasLoad(insn: Instruction): Boolean =
    insn.getPcode().exists(pc => pc.getOpcode == PcodeOp.LOAD)

  def pcodeOpToTypeHint(
      program: Program,
      pc: PcodeOp,
      sol: TypeSolution,
      aliases: MutableMap[Long, TypeSpec]
  ): Option[TypeHint] =
    sol
      .get_sol(Op(pc))
      .flatMap(dty => {
        val reg = program.getRegister(pc.getOutput)
        val valspec = ValueSpec(
          ValueSpec.InnerValue.Reg(RegSpec(getRegisterName(reg)))
        )

        val typespec = getTypeSpec(dty, aliases)
        typespec.map(ty => {
          val varspec = VariableSpec(Seq(valspec), Some(ty))
          TypeHint(pc.getSeqnum.getTarget.getOffset, Some(varspec))
        })
      })

  def computeTypeHints(
      func: Function,
      aliases: MutableMap[Long, TypeSpec]
  ): List[TypeHint] =
    val cons = TypeAnalysis(func).analyze()
    val sol = TypeSolvingContext().solve(cons)
    // now we get all pcodeops that assign an output register, are the unique assigner of the output register,
    // the instruction contains a load, and have a type
    val func_insns: ju.Iterator[Instruction] = func.getProgram.getListing
      .getInstructions(func.getBody, true)
    val res = func_insns.asScala
      .filter(insnHasLoad)
      .flatMap(outputRegAssignersForInstruction)
      .flatMap(pcodeOpToTypeHint(func.getProgram, _, sol, aliases))
      .toList
    res

  def specifyFunction(
      func: Function,
      defaultRetAddr: Option[ValueSpec],
      aliases: MutableMap[Long, TypeSpec],
      linkage: FunctionLinkage,
      func_split_addrs: Set[Address],
      zero_byte_addrs: Set[Address]
  ): FuncSpec = {

    val params = func.getParameters().toSeq.map(x => specifyParam(x, aliases))
    val retValue =
      Option(func.getReturn()).map(x => specifyVariable(x, aliases))
    var cfg = if func.isExternal() then { Map.empty }
    else { getCFG(func, func_split_addrs) }

    if (!cfg.exists((_, blk) => blk.address == func.getEntryPoint.getOffset)) {
      cfg = Map.empty
    }
    val cdi = CallDepthChangeInfo(func, TaskMonitor.DUMMY)
    val max_depth = maxDepth(func, cdi)
    val bb_context_prod = BasicBlockContextProducer(func, cdi, max_depth, cfg)
    var block_ctxts: Map[Long, BlockContextSpec] = cfg
      .map((uid, cb) => {
        (
          uid,
          bb_context_prod.getBlockContext(cb)
        )
      })
      .to(SortedMap)

    if (zero_byte_addrs.nonEmpty) {
      val cfg_n_block_ctxts = BasicBlockSplit.insertZeroByteBlocks(
        cfg,
        block_ctxts,
        zero_byte_addrs.map(_.getOffset)
      )
      cfg = cfg_n_block_ctxts._1
      block_ctxts = cfg_n_block_ctxts._2
    }

    val ty_hints = computeTypeHints(func, aliases)
    val prog_addr = getProgramBinaryAddress(func.getSymbol)
    val entry_addr =
      getThunkRedirection(func.getProgram, func.getEntryPoint).getOffset
    val entry_uid = cfg
      .find((_, blk) => blk.address == func.getEntryPoint.getOffset)
      .map(_._2.uid)
      .getOrElse(0L)
    FuncSpec(
      entry_addr,
      entry_uid,
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
      block_ctxts,
      Some(getStackEffects(func, aliases)),
      Some(
        StackFrame(
          func.getStackFrame.getFrameSize,
          func.getStackFrame.getReturnAddressOffset,
          func.getStackFrame.getParameterSize,
          max_depth,
          func.getStackFrame.getParameterOffset
        )
      ),
      getInScopeVars(func.getProgram(), block_ctxts).toSeq,
      ty_hints,
      prog_addr
    )
  }

  def getProgramBinaryAddress(symbol: Symbol): Option[ProgramAddress] = {
    // Check if symbol is internal
    if (!symbol.isExternal) {
      val entry_addr =
        getThunkRedirection(symbol.getProgram, symbol.getAddress).getOffset
      return Some(
        ProgramAddress(ProgramAddress.Inner.InternalAddress(entry_addr))
      )
    }

    // Check if we have a GOT address for the external symbol. This is usually
    // the case unless the user has manually added a new symbol that the program
    // didn't originally use
    getGotAddr(symbol)
      .map(addr =>
        ProgramAddress(
          ProgramAddress.Inner.ExtAddress(RelativeAddress(addr.getOffset))
        )
      ) match {
      case Some(progAddr) => return Some(progAddr)
      case None           => // continue
    }

    // The user has maually added a symbol that the program didn't originally
    // use. Now, we search for a symbol that is close to this new symbol in the
    // external program and return this information
    val extProg = getLinkedExternalProgram(symbol)
      .getOrElse {
        Msg.error(
          this,
          "Could not find linked external library program for symbol: " + symbol
        )
        return None
      }
    val extLocation = getExternalLocation(symbol)
      .getOrElse {
        Msg.error(
          this,
          "Could not find external location in " + extProg + " for symbol " + symbol
        )
        return None
      }
    val extSymName = extLocation.getSymbol.getName
    val extSymbol = getLocalSymbolByName(extProg, extSymName)
      .getOrElse {
        Msg.error(
          this,
          "Could not find local symbol '" + extSymName + "' in " + extProg
        )
        return None
      }

    val prog = symbol.getProgram
    // Search for the closest external symbol to the manually defined symbol
    val minExtOffSymbol = prog.getSymbolTable.getExternalSymbols
      .iterator()
      .asScala
      .filter(symbol =>
        getSymbolLibraryName(symbol)
          .exists(libName =>
            libName == extLocation.getLibraryName && getGotAddr(
              symbol
            ).isDefined
          )
      )
      .flatMap(symbol => getLocalSymbolByName(extProg, symbol.getName))
      .minBy(symbol =>
        abs(symbol.getAddress.getOffset - extSymbol.getAddress.getOffset)
      )

    val offset =
      extSymbol.getAddress.getOffset - minExtOffSymbol.getAddress.getOffset
    for {
      offSymbol <- getExtSymbolByName(prog, minExtOffSymbol.getName)
      gotOffAddr <- getGotAddr(offSymbol)
    } yield ProgramAddress(
      ProgramAddress.Inner.ExtAddress(
        RelativeAddress(gotOffAddr.getOffset, offset)
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

    val call_target_addr = references.headOption
      .map(x => x.getToAddress())
      .map(x => get_thunk_redirection(x))
    val noreturn = call_target_addr
      .flatMap(a => function_at_addr(a))
      .map(f => f.hasNoReturn())
      .getOrElse(false);
    val call_target_offset = call_target_addr
      .map(a => a.getOffset())

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
              /*noreturn*/ noreturn,
              /*targetAddress=*/ call_target_offset
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
              /*noreturn*/ noreturn,
              /*targetAddress=*/ call_target_offset
            )
          )
        );

      } else {
        val noreturn = false;
        // if there is no fallthrough and there is a call, treat as stop
        return Some(
          ControlFlowOverride.SCall(
            Call(
              addr,
              /*returnAddress=*/ None,
              /*isTailcall=*/ false,
              /*stop=*/ true,
              /*noreturn=*/ noreturn,
              /*targetAddress=*/ call_target_offset
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
    val prog_addr = getProgramBinaryAddress(symbol)
    Option(listing.getDataAt(addr))
      .filter(_ => symbol.getSymbolType() != SymbolType.FUNCTION)
      .flatMap(data => Option(data.getDataType()))
      .map(datatype =>
        GlobalVariable(
          getTypeSpec(datatype, aliases),
          addr.getOffset(),
          prog_addr
        )
      )
  }

  def specifyFunctionOrDecl(
      func: Function,
      defaultRetAddr: Option[ValueSpec],
      aliases: MutableMap[Long, TypeSpec],
      as_decl: Boolean,
      func_split_addrs: Set[Address],
      zero_byte_addrs: Set[Address]
  ): FuncSpec = {
    val linkage = (as_decl, func.isExternal()) match {
      case (_, true) => FunctionLinkage.FUNCTION_LINKAGE_EXTERNAL
      case (true, _) =>
        FunctionLinkage.FUNCTION_LINKAGE_DECL
      case _ => FunctionLinkage.FUNCTION_LINKAGE_NORMAL_UNSPECIFIED
    }

    specifyFunction(
      func,
      defaultRetAddr,
      aliases,
      linkage,
      func_split_addrs,
      zero_byte_addrs
    )
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
          sig.getCallingConventionName
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
      function_decl_list: Seq[Function],
      function_split_addrs_in: Set[Address] = Set.empty,
      required_globals: Set[Symbol] = Set.empty,
      zero_byte_addrs: Set[Address] = Set.empty
  ): Specification = {
    val function_split_addrs: Set[Address] =
      if function_split_addrs_in.isEmpty then
        SplitsManager(prog).getSplits().asScala.map(_._2).toSet
      else function_split_addrs_in
    val aliases = MutableMap[Long, TypeSpec]()
    val arch = getProgramArch(prog)
    val os = getProgramOS(prog)
    val image_name = prog.getName();
    val image_base = prog.getImageBase().getOffset();
    val listing = prog.getListing()
    val memory = prog.getMemory()
    val funcmgr = prog.getFunctionManager()
    val defaultRetAddr = specifyDefaultReturnAddress(prog)

    val required_funcs = required_globals.flatMap(sym =>
      Option(prog.getFunctionManager().getFunctionAt(sym.getAddress()))
    )

    val func_defs_redirected = applyThunkRedirections(prog, function_def_list)
    val func_decls_redirected =
      applyThunkRedirections(
        prog,
        function_decl_list ++ required_funcs
      ) -- func_defs_redirected
    Msg.info(this, "Func decls redirected: " + func_decls_redirected.toString)
    val func_specs = (func_decls_redirected.toSeq
      .sortBy(_.getEntryPoint)
      .map(
        specifyFunctionOrDecl(
          _,
          defaultRetAddr,
          aliases,
          true,
          function_split_addrs,
          zero_byte_addrs
        )
      ) ++ func_defs_redirected.toSeq
      .sortBy(_.getEntryPoint)
      .map(
        specifyFunctionOrDecl(
          _,
          defaultRetAddr,
          aliases,
          false,
          function_split_addrs,
          zero_byte_addrs
        )
      )).toList.sortBy(_.entryAddress)

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
      .filter(block => !block.isExternalBlock())
      .filter(block => block.isLoaded())
      // Ignore blocks that are both empty and not writeable, since they would be useless anyway
      .filter(block => block.isWrite() || block.getSize() > 0)
      // Ignore overlay blocks to avoid overlapping memory
      .filter(block => !block.isOverlay())
      .map(specifyMemoryBlock)
    val global_specs = {
      func_defs_redirected
        .flatMap(getGlobalsFromFunction)
        .flatMap(x => specifyGlobalVariable(x, aliases))
        ++ required_globals.toSeq
          .flatMap(sym => specifyGlobalVariable(sym, aliases))
    }

    val callsite_overrides =
      func_defs_redirected.toSeq
        .flatMap(getOverridesCallsitesForFunction)
        .flatMap((insn, dsm) =>
          specifyCallsite(insn, dsm, defaultRetAddr, aliases)
        )

    val type_names = aliases.view
      .flatMap((tid, _) => {
        Option(prog.getDataTypeManager.findDataTypeForID(UniversalID(tid)))
          .flatMap(dt => Option.when(dt.isInstanceOf[Composite])(dt))
          .map(dt => (tid, dt.getName()))
      })
      .toMap

    Specification(
      arch,
      os,
      func_specs,
      callsite_overrides,
      global_specs.toArray.toSeq,
      symbol_specs.toArray.toSeq,
      mem_specs.toArray.toSeq,
      Some(specifyControlFlow(prog)),
      aliases.view.toMap,
      image_name,
      image_base,
      required_globals.map(_.getName).toSeq,
      type_names
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

  def already_overlaps_func(
      target_function: Function,
      blk: CodeBlock
  ): Boolean = {
    val res = blk
      .getAddressRanges()
      .iterator()
      .asScala
      .exists(range =>
        target_function
          .getProgram()
          .getFunctionManager()
          .getFunctionsOverlapping(AddressSet(range))
          .asScala
          .exists(f => {
            val res = f != target_function
            if (res) {
              Msg.info(this, "Overlaps: " + f.getName())
            }
            res
          })
      )

    Msg.info(this, "Filtering block: " + blk)

    res
  }

  def makeFunctionsPermissive(funcs: Seq[Function]) = {
    funcs.foreach(f => {
      val addrs = AddressSet()
      val reachable = getReachableCodeBlocks(f)
      val prog = f.getProgram()
      if (!reachable.isEmpty) {
        reachable
          .filter(!already_overlaps_func(f, _))
          .foreach(
            _.getAddressRanges()
              .iterator()
              .asScala
              .foreach(addrs.add(_))
          )
        if (addrs.contains(f.getEntryPoint())) {
          f.setBody(addrs)
        }
      }
    })
  }

  def specifySingleFunction(
      func: Function,
      required_globals: Set[Symbol] = Set.empty
  ) = {
    val splits_man = SplitsManager(func.getProgram)
    Msg.info(this, "Required globals: " + required_globals.toString)
    specifySingleFunctionWithSplits(
      func,
      splits_man.getSplitsForAddressJava(func.getEntryPoint),
      required_globals,
      splits_man.getZeroBlocksForAddressJava(func.getEntryPoint)
    )
  }

  def specifySingleFunctionWithSplits(
      func: Function,
      func_split_addrs: ju.Set[Address],
      required_globals: Set[Symbol],
      zero_byte_addrs: ju.Set[Address]
  ) = {
    makeFunctionsPermissive(Seq(func))
    val decls = calledFunctions(func)
    specifyProgram(
      func.getProgram(),
      List(func),
      decls.toSeq,
      if (func_split_addrs == null) Set.empty
      else func_split_addrs.asScala.toSet,
      if (required_globals == null) Set.empty else required_globals,
      if (zero_byte_addrs == null) Set.empty
      else zero_byte_addrs.asScala.toSet
    )
  }

  def specifyFunctions(
      program: Program,
      funcs: java.lang.Iterable[Function]
  ): Specification = {
    val func_col = funcs.iterator().asScala.toSeq
    makeFunctionsPermissive(func_col)
    val decls = func_col.flatMap(calledFunctions)
    specifyProgram(program, func_col, decls)
  }

  def specifyProgram(prog: Program): Specification = {
    val it: ju.Iterator[Function] = prog.getFunctionManager().getFunctions(true)
    val funcs = it.asScala.toSeq
    makeFunctionsPermissive(funcs)
    specifyProgram(prog, funcs, Seq.empty)
  }
}
