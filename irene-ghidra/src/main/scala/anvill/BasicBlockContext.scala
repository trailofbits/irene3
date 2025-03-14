package anvill
import ghidra.program.model.listing.Function
import ghidra.program.model.address.Address
import ghidra.app.cmd.function.CallDepthChangeInfo
import collection.JavaConverters._
import ghidra.program.model.lang.Register
import specification.specification.{BlockContext => BlockContextSpec}
import specification.specification.{CodeBlock => CodeBlockSpec}
import specification.specification.{Register => RegSpec}
import specification.specification.{Value => ValueSpec}
import specification.specification.{Variable => VariableSpec}
import specification.specification.{Parameter => ParamSpec}
import specification.specification.TypeSpec
import specification.specification.{ValueMapping => ValueMapSpec}
import specification.specification.ValueDomain
import ghidra.util.Msg
import ghidra.program.model.lang.Register
import Util.registerToVariable
import specification.specification.HighSymbol
import ghidra.program.model.listing.Variable
import ghidra.program.model.listing.Parameter
import specification.specification.HighLoc
import specification.specification.SymbolMapping
import ghidra.program.model.data.Structure

object BasicBlockContextProducer {
  def validDepth(maybe_dpth: Int): Boolean =
    maybe_dpth != Function.INVALID_STACK_DEPTH_CHANGE && maybe_dpth != Function.UNKNOWN_STACK_DEPTH_CHANGE
}

class BasicBlockContextProducer(
    gfunc: Function,
    stack_depth_info: CallDepthChangeInfo,
    val max_depth: Long,
    cfg: Map[Long, CodeBlockSpec]
) {

  val aliases: scala.collection.mutable.Map[Long, TypeSpec] =
    scala.collection.mutable.Map.empty

  val live_analysis =
    LivenessAnalysis(
      gfunc,
      stack_depth_info,
      aliases,
      cfg
    )
  val liveness_info = live_analysis
    .getBlockLiveness()

  // The conditions under which getRegDepth can succeed...
  def hasPredecessorInsn(block_addr: Address): Boolean = {
    val curr_insn = Option(
      this.gfunc.getProgram().getListing().getInstructionAt(block_addr)
    )
    curr_insn
      .flatMap(insn => Option(insn.getFallFrom()))
      .flatMap(addr => Option(addr))
      .isDefined
  }

  def produceSymvals(
      block_addr: Address,
      additional_displacement: Int
  ): Map[Register, Int] = {

    val regs = gfunc.getProgram.getLanguage.getRegisters.asScala.filter(r =>
      r.getBitLength == gfunc.getProgram.getLanguage.getProgramCounter.getBitLength
    )

    if (!hasPredecessorInsn(block_addr)) {
      // This handles a bug in Ghidra. The function getRegDepth is ill defined if there is not a fallfrom
      // predecessor. We should probably replace these wholesale when value analysis is done. This case mostly happens
      // at function entries tho in which case we wont have a symval for a register besides the stack pointer anyways so we are mostly ok.
      return (for {
        sp <- Option(gfunc.getProgram().getCompilerSpec().getStackPointer())
        dpth <- {
          val maybe_dpth = stack_depth_info.getDepth(block_addr)
          if (BasicBlockContextProducer.validDepth(maybe_dpth))
          then Some(maybe_dpth)
          else None
        }
      } yield (sp, dpth)).toMap
    }

    regs
      .map(r => (r, stack_depth_info.getRegDepth(block_addr, r)))
      .filter((_, dpth) => BasicBlockContextProducer.validDepth(dpth))
      .map((r, dpth) => (r, dpth + additional_displacement))
      .toMap
  }

  def liveness(block: CodeBlockSpec): BlockLiveness = {
    liveness_info(block)
  }

  def paramSpecToRegister(p: ParamSpec): Option[Register] = {
    val vs = p.reprVar.get
    if vs.values.length != 1 then { None }
    else {
      val v = vs.values(0)
      v.innerValue.reg.flatMap(r =>
        Option(gfunc.getProgram().getLanguage().getRegister(r.registerName))
      )
    }
  }

  def sdepths_to_filter(sdepths: Map[Register, Int]): ParamSpec => Boolean =
    p => paramSpecToRegister(p).map(r => !sdepths.contains(r)).getOrElse(true)

  def getStackOffset(p: ParamSpec): Option[Long] = {
    for {
      vr <- p.reprVar
      value <- if vr.values.length == 1 then Some(vr.values(0)) else None
      mem_depth <- value.innerValue.mem.map(_.offset)
    } yield mem_depth
  }

  def isOffsetInsStack(curr_dpth: Long, off: Long): Boolean = {

    val frame = this.gfunc.getStackFrame()
    // TODO(Ian): we probably shouldnt have longs anyways
    val targetVar = frame.getVariableContaining(off.toInt)
    if (targetVar == null) {
      return false
    }

    val sz = targetVar.getLength()

    val grows_neg = frame.growsNegative()
    val dpth = (if grows_neg then -(curr_dpth.abs) else curr_dpth)

    (grows_neg && off >= dpth && off + sz < frame.getParameterOffset() + frame
      .getParameterSize()) ||
    (!grows_neg && off <= dpth && off - sz > frame
      .getParameterOffset() - frame.getParameterSize())
  }

  def filterStackLocationsByStackDepth(
      dpth: Long,
      locs: Seq[ParamSpec]
  ): Seq[ParamSpec] = {
    locs.filter(p =>
      getStackOffset(p)
        .map(
          isOffsetInsStack(dpth, _)
        )
        .getOrElse(true)
    )
  }

  val AllowedConstRegisterNames = Map(
    "PowerPC:BE:64:VLE-32addr" -> Seq(("R13", true, None), ("R2", true, None)),
    "PowerPC:BE:32:e200:VLE" -> Seq(("R13", true, None), ("R2", true, None)),
    "sparc:BE:32:default" -> Seq(
      ("DECOMPILE_MODE", false, Some(1)),
      ("didrestore", false, Some(0))
    )
  )

  def produceGlobalRegOverrides(block_addr: Address): Seq[ValueMapSpec] = {
    val ctxt = gfunc.getProgram().getProgramContext()

    AllowedConstRegisterNames
      .getOrElse(
        gfunc.getProgram().getLanguage().getLanguageID().getIdAsString(),
        Seq.empty
      )
      .collect(
        scala.Function.unlift((rname, should_taint_by_pc, default_val) => {
          val reg = gfunc.getProgram().getRegister(rname)
          Option(ctxt.getRegisterValue(reg, block_addr)).flatMap(reg_val =>
            if (reg_val.hasValue()) {
              Some(
                ValueMapSpec(
                  Some(registerToVariable(reg)),
                  Some(
                    ValueDomain(
                      ValueDomain.Inner
                        .Constant(
                          specification.specification.Constant(
                            reg_val.getUnsignedValue().longValue(),
                            should_taint_by_pc
                          )
                        )
                    )
                  )
                )
              )
            } else if (default_val.isDefined) {
              Some(
                ValueMapSpec(
                  Some(registerToVariable(reg)),
                  Some(
                    ValueDomain(
                      ValueDomain.Inner
                        .Constant(
                          specification.specification.Constant(
                            default_val.get,
                            should_taint_by_pc
                          )
                        )
                    )
                  )
                )
              )
            } else {
              None
            }
          )
        })
      )

  }

  def getGhidraAddress(addr: Long): Address = {
    this.gfunc.getProgram.getAddressFactory.getDefaultAddressSpace
      .getAddress(addr)
  }

  def getBlockContext(
      blk: CodeBlockSpec
  ): BlockContextSpec = {
    val block_addr = this.getGhidraAddress(blk.address)
    val last_insn_addr = this.gfunc.getProgram.getListing
      .getInstructionBefore(this.getGhidraAddress(blk.address + blk.size))
      .getAddress()
    Msg.info(this, s"Working on context for $block_addr")
    assert(!liveness_info.isEmpty)

    val stack_depths_entry = produceSymvals(block_addr, 0)
    val global_reg_overrides = produceGlobalRegOverrides(block_addr)
    val last_insn_disp = stack_depth_info.getInstructionStackDepthChange(
      gfunc.getProgram().getListing().getInstructionAt(last_insn_addr)
    )
    val stack_depths_exit =
      if last_insn_disp != Function.UNKNOWN_STACK_DEPTH_CHANGE then
        produceSymvals(last_insn_addr, last_insn_disp)
      else Map.empty
    val stack_reg = gfunc.getProgram.getCompilerSpec().getStackPointer()
    val live = this.liveness(blk)

    BlockContextSpec(
      stack_depths_entry
        .map((reg, dpth) => {
          ValueMapSpec(
            Some(registerToVariable(reg)),
            Some(ValueDomain(ValueDomain.Inner.StackDisp(dpth)))
          )

        })
        .toSeq ++ global_reg_overrides,
      stack_depths_exit
        .map((reg, dpth) => {
          ValueMapSpec(
            Some(registerToVariable(reg)),
            Some(ValueDomain(ValueDomain.Inner.StackDisp(dpth)))
          )
        })
        .toSeq ++ global_reg_overrides,
      // TODO(Ian): filter by curr depth
      filterStackLocationsByStackDepth(
        max_depth,
        live.live_before.filter(sdepths_to_filter(stack_depths_entry)).toSeq
      ),
      filterStackLocationsByStackDepth(
        max_depth,
        live.live_after.filter(sdepths_to_filter(stack_depths_exit)).toSeq
      )
    )
  }
}
