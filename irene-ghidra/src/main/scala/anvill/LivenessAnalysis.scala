package anvill

import java.util as ju
import scala.collection.mutable
import scala.collection.immutable
import ghidra.program.model.address.{Address, AddressSet, AddressSpace}
import ghidra.program.model.block.CodeBlock
import ghidra.program.model.lang.{Language, Register}
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.listing.{
  FunctionSignature,
  Instruction,
  Program,
  Variable
}

import collection.JavaConverters.*
import ghidra.app.cmd.function.CallDepthChangeInfo
import specification.specification.CodeBlock as CodeBlockSpec
import specification.specification.Value as ValueSpec
import specification.specification.Memory as MemSpec
import specification.specification.Register as RegSpec
import specification.specification.Variable as VarSpec
import specification.specification.Parameter as ParamSpec
import specification.specification.Value.InnerValue as ValueInner
import ghidra.program.model.data.Structure
import Util.{ProgramAnalysisUtilMixin, registerToVariable}

import scala.collection.immutable.Set
import scala.collection.Set as MutableSet
import ProgramSpecifier.getRegisterName
import ProgramSpecifier.getOverrideForInsn
import anvill.Fixpoint.Solution
import ghidra.program.model.pcode.Varnode
import ghidra.program.model.lang.Register
import specification.specification.TypeSpec
import ghidra.util.task.TaskMonitor
import ghidra.util.Msg
import ghidra.program.model.block.BasicBlockModel
import ghidra.program.model.symbol.FlowType

case class BlockLiveness(
    val live_before: Set[ParamSpec],
    val live_after: Set[ParamSpec]
)

object LiveAddresses {
  val empty: LiveAddresses = LiveAddresses(Set.empty)

  def from(x: IterableOnce[Varnode]): LiveAddresses =
    LiveAddresses.empty ++ x
}

// the way im currently doing this is way in-efficient
// an AVL tree is not an efficient way to merge sets of addresses map->itv for instance would be more efficient
case class LiveAddresses(live_addrs: Set[Address]) extends Iterable[Varnode]:
  override def iterator: Iterator[Varnode] =
    live_addrs.iterator.map(Varnode(_, 1))
  infix def +(x: Varnode): LiveAddresses =
    val res = LiveAddresses(
      live_addrs ++ (0 until x.getSize).map(off => x.getAddress.add(off))
    )
    res
  infix def -(x: Varnode): LiveAddresses =
    LiveAddresses(
      live_addrs -- (0 until x.getSize).map(off => x.getAddress.add(off))
    )

  def --(x: IterableOnce[Varnode]): LiveAddresses =
    x.iterator.foldLeft(this)(_ - _)

  def ++(x: IterableOnce[Varnode]): LiveAddresses =
    x.iterator.foldLeft(this)(_ + _)

  def join(x: LiveAddresses): LiveAddresses =
    LiveAddresses(live_addrs ++ x.live_addrs)

  def meet(x: LiveAddresses): LiveAddresses =
    LiveAddresses(live_addrs & x.live_addrs)
end LiveAddresses

object LivenessAnalysis {
  type D = LiveAddresses

  given reaching_lat: JoinSemiLattice[LiveAddresses] with
    override val bot: LiveAddresses = LiveAddresses(Set.empty)

    override def join(lhs: LiveAddresses, rhs: LiveAddresses): LiveAddresses =
      lhs.join(rhs)

    override def lteq(x: LiveAddresses, y: LiveAddresses): Boolean =
      x.live_addrs.subsetOf(y.live_addrs)

    override def tryCompare(x: LiveAddresses, y: LiveAddresses): Option[Int] =
      if x.live_addrs.equals(y.live_addrs) then Some(0)
      else if x.live_addrs.subsetOf(y.live_addrs) then Some(-1)
      else if y.live_addrs.subsetOf(x.live_addrs) then Some(1)
      else None
}

class RegInfo(private val language: Language):
  def merge_set(l: List[(Address, Register)]): List[(Address, Set[Register])] =
    l.groupBy(_._1)
      .map((addr, elems) => (addr, elems.map(e => e._2).toSet))
      .toList
  // inclusive
  val start_keys = immutable.SortedMap.from(
    merge_set(language.getRegisters.asScala.toList.map(r => (r.getAddress, r)))
  )
  // exclusive
  val end_keys = immutable.SortedMap.from(
    merge_set(
      language.getRegisters.asScala.toList.map(r =>
        (r.getAddress.add(r.getNumBytes), r)
      )
    )
  )

  def get_containing_regs(addr: Address): Set[Register] =
    val startset = start_keys.rangeTo(addr).iterator.flatMap(_._2).toSet
    // range from is inclusive and we only want keys that end after our address
    val endset = end_keys.rangeFrom(addr.add(1)).iterator.flatMap(_._2).toSet
    startset & endset
end RegInfo

/** Reverse dataflow analysis over the CFG for register liveness
  *
  * @param control_flow_graph
  *   the control flow graph
  * @param func
  *   the function
  */
class LivenessAnalysis(
    val func: ghidra.program.model.listing.Function,
    val cdi: CallDepthChangeInfo,
    val aliases: scala.collection.mutable.Map[Long, TypeSpec],
    val blks: Map[Long, CodeBlockSpec]
) extends ProgramAnalysisUtilMixin
    with PcodeFixpoint[LivenessAnalysis.D] {
  val rinfo = RegInfo(func.getProgram.getLanguage)
  val unmodeled_calling_conventions: List[String] = List("SPARC")

  val should_include_unaffected_list: Boolean = {
    val procstr = func.getProgram.getLanguage.getProcessor.toString
    !unmodeled_calling_conventions.exists(ov_id => procstr.contains(ov_id))
  }

  val prog: Program = func.getProgram
  val lang = func.getProgram().getLanguage()
  val register_to_variable: Map[Register, Variable] =
    func
      .getAllVariables()
      .flatMap(v =>
        (Option(v.getRegisters()).toSeq.flatMap(_.asScala.map((_, v))))
      )
      .toMap

  def registerToParam(r: Register): ParamSpec = {
    register_to_variable
      .get(r)
      .map(v => specifyVariable(v))
      .getOrElse(
        ParamSpec(Some(getRegisterName(r)), Some(registerToVariable(r)))
      )

  }

  def specifyVariable(
      v: Variable
  ): ParamSpec = {
    ParamSpec(
      Some(v.getName()),
      Some(ProgramSpecifier.specifyVariable(v, aliases))
    )
  }

  // We refuse to pair registers on SPARC
  private val sparc_pair_reg_names = (for {
    x <- 0 until 7 by 2; y <- List("g", "o", "l", "i")
  } yield (x, y)).map((ind, rname) =>
    (s"$rname${ind}_${ind + 1}", List(s"$rname$ind", s"$rname${ind + 1}"))
  ) :+ ("fp_7", List("fp", "i7")) :+ ("sp_7", List("sp", "o7"))
  private val forced_splits =
    (if lang.getProcessor.toString.contains("Sparc") then
       sparc_pair_reg_names
         .map((to_split, into) =>
           (lang.getRegister(to_split), into.map(s => lang.getRegister(s)))
         )
         .toMap
     else Map())

  def collect_live_regs(addr: Iterator[Address]): Seq[Register] =
    // Select the smallest register for each base reg that covers all live regs.
    // TODO(Ian): we dont handle splitting within a base reg
    def get_repr_base(i: IterableOnce[Register]) =
      i.iterator.filter(r => r.isBaseRegister).nextOption()

    val res: List[Set[Register]] = addr
      .flatMap(a => {
        val regs_containing_address = rinfo.get_containing_regs(a)
        get_repr_base(regs_containing_address).map((_, regs_containing_address))
      })
      .toList
      .groupBy((r, _) => r)
      .map(
        (
            _,
            covering_regs_for_mems_of_base_reg: List[(Register, Set[Register])]
        ) => {
          val st = covering_regs_for_mems_of_base_reg.headOption
          st.toSet.flatMap(st =>
            covering_regs_for_mems_of_base_reg.foldLeft(st._2)((tot, arr) => {
              tot & arr._2
            })
          )
        }
      )
      .toList
    Msg.info(this, s"forced_splits $forced_splits")
    res
      .flatMap(s => s.minByOption(r => r.getNumBytes))
      .flatMap(r => forced_splits.getOrElse(r, List(r)))

  def params_from_live(l: LiveAddresses): Set[ParamSpec] =
    val stacks = l.live_addrs
      .filter(a => a.isStackAddress)
      .map(a => func.getStackFrame.getVariableContaining(a.getOffset.toInt))
      .map(specifyVariable)
    val regs = collect_live_regs(
      l.live_addrs.filter(a => a.isRegisterAddress).toSeq.iterator
    )
    regs.map(registerToParam).toSet ++ stacks

  def local_paramspecs(): LiveAddresses = {
    LiveAddresses.from(
      func.getAllVariables.toSeq
        .filter(v => v.isStackVariable)
        .flatMap(v => v.getVariableStorage.getVarnodes)
    )
  }

  // TODO(Ian) right now we gen all stack vars for any load
  // We could be missing a var for part of the stack becuase of how ghidra does locals
  // Need to conservatively split the stack, also need a backing alias analysis
  def gen_stack_vars(op: PcodeOp): LiveAddresses = {
    if (op.getOpcode() == PcodeOp.LOAD) {
      local_paramspecs()
    } else { LiveAddresses.empty }
  }

  // The safe assumption is we kill nothing
  def kill_stack_vars(op: PcodeOp) = {
    LiveAddresses.empty
  }

  def getUniqueCallee(
      insn: Instruction
  ): Option[ghidra.program.model.listing.Function] = {
    val call_refs =
      insn.getReferencesFrom().filter(p => p.getReferenceType().isCall())

    if (call_refs.length != 1) {
      return None
    }

    Option(
      func
        .getProgram()
        .getFunctionManager()
        .getFunctionAt(call_refs(0).getToAddress())
    )
  }

  def get_live_registers(vars: Seq[Variable]): Set[Register] = {
    vars
      .flatMap(v =>
        Option(v.getRegisters()).map(rs => rs.asScala).getOrElse(Seq.empty)
      )
      .toSet
  }

  def kill_call_live(insn: Instruction, op: PcodeOp): LiveAddresses = {
    if (op.getOpcode() == PcodeOp.CALL || op.getOpcode == PcodeOp.CALLIND) {
      LiveAddresses.from(
        getUniqueCallee(insn)
          .flatMap(f => Option(f.getReturn()))
          .flatMap(r => Option(r.getRegisters()).map(r => r.asScala))
          .getOrElse(Seq.empty)
          .map(r => Varnode(r.getAddress, r.getNumBytes))
      )
    } else {
      LiveAddresses.empty
    }
  }

  def live_call_set(insn: Instruction): LiveAddresses =
    LiveAddresses.from(
      getUniqueCallee(insn)
        .map(f =>
          getOverrideForInsn(insn) match
            case Some(dsm) =>
              val sig = dsm.getDataType.asInstanceOf[FunctionSignature]
              val prog = f.getProgram()
              val compiler_spec = prog.getCompilerSpec()
              val proto = Option(
                compiler_spec.getCallingConvention(sig.getCallingConventionName)
              )
                .getOrElse(compiler_spec.getDefaultCallingConvention())
              val types = Array(sig.getReturnType()) ++ sig
                .getArguments()
                .map(param => param.getDataType())

              val locs = proto.getStorageLocations(prog, types, false)
              // first element is the return storage which we don't care about
              val o = locs
                .drop(1)
                .toSeq
                .flatMap(p =>
                  Option(p.getRegisters())
                    .map(rs => rs.asScala)
                    .getOrElse(Seq.empty)
                )
              Msg.info(this, "Overriden call " + insn + ": " + o)
              o
            case None =>
              get_live_registers(f.getParameters().toSeq)
        )
        .getOrElse(Seq.empty)
        .map(r => Varnode(r.getAddress, r.getNumBytes))
    )

  def gen_call_live(insn: Instruction, op: PcodeOp): LiveAddresses = {
    if (op.getOpcode() == PcodeOp.CALL || op.getOpcode == PcodeOp.CALLIND) {
      // TODO(Ian): this assumes that we arent going to build up a stack parameter in a calling block
      // this requires handling stack extensions, which we dont handle... this could come up with something like int a; if (x<0) a= b else a = c; call(a)
      // A reasonable thing for a compile to do would be to either push b or c to the stack in each of those blocks.
      live_call_set(insn)
    } else {
      LiveAddresses.empty
    }
  }

  def gen_registers(op: PcodeOp): LiveAddresses = {
    val read_regs = op
      .getInputs()
      .map(vnode =>
        Option(lang.getRegister(vnode.getAddress(), vnode.getSize())).map(reg =>
          reg
        )
      )
    LiveAddresses.from(
      read_regs.flatten.map(r => Varnode(r.getAddress, r.getNumBytes))
    )
  }

  // TODO(Ian): Call pcodeops should kill returns
  def kill_registers(op: PcodeOp): LiveAddresses = {
    val out = Option(op.getOutput())
    LiveAddresses.from(
      out
        .flatMap(vnode =>
          Option(lang.getRegister(vnode.getAddress(), vnode.getSize()))
        )
        .map(r => Varnode(r.getAddress, r.getNumBytes))
    )

  }

  def gen(op: PcodeOp, insn: Instruction): LiveAddresses = {
    val svars = gen_stack_vars(op)
    val gcall = gen_call_live(insn, op)
    val gregs = gen_registers(op)

    svars ++ gcall ++ gregs
  }

  def kill(op: PcodeOp, insn: Instruction): LiveAddresses = {
    val killed =
      kill_registers(op) ++ kill_stack_vars(op) ++ kill_call_live(insn, op)
    killed
  }

  def transfer(
      insn: Instruction,
      n: PcodeOp,
      live_after: LiveAddresses
  ): LiveAddresses = {
    val killed = kill(n, insn)
    val genned = gen(n, insn)
    (live_after -- killed) ++ genned
  }

  def get_return_liveness(): LiveAddresses = {
    val r = get_live_registers(Option(func.getReturn()).toSeq).map(r =>
      Varnode(r.getAddress, r.getNumBytes)
    )
    LiveAddresses.from(r)
  }
  def get_initial_after_liveness(addr: Address): LiveAddresses = {
    val insn = prog.getListing.getInstructionAt(addr)
    val flow = insn.getFlowType

    if (flow.isCall && flow.isTerminal) {
      live_call_set(insn)
    } else {
      // If a block can return then the saves need to be live at that point,
      // + returns
      // Returns no longer need to be considered live with tail calling representations
      // Native returns already lift the return value
      val res = (if should_include_unaffected_list then
                   val op_regs = Option(
                     func
                       .getCallingConvention()
                   ).getOrElse(
                     func
                       .getProgram()
                       .getCompilerSpec()
                       .getDefaultCallingConvention()
                   ).getUnaffectedList()
                     .toSet
                     .filter(vnode => vnode.isRegister())
                   val unaff = LiveAddresses.from(op_regs)
                   (unaff
                     ++ get_return_liveness())
                 else LiveAddresses.empty)
      res
    }
  }

  def get_liveness_entrypoints(
      cfg: ComputeNodeContext.CFG
  ): Map[CfgNode, LiveAddresses] = {
    cfg.nodes
      .filter(_.outgoing.isEmpty)
      .map(x => {
        (x.outer, get_initial_after_liveness(x.outer.getAddress))
      })
      .toMap
  }

  def getNextLocalDepth(): Int = {
    val stack = func.getStackFrame()
    if (stack.growsNegative()) {
      // shift by the return address location so we only include the negative portion
      (-stack.getLocalSize()) + stack.getParameterOffset()
    } else {
      stack.getLocalSize()
    }
  }

  def validDepth(dpth: Int): Boolean =
    dpth != ghidra.program.model.listing.Function.UNKNOWN_STACK_DEPTH_CHANGE
      && dpth != ghidra.program.model.listing.Function.INVALID_STACK_DEPTH_CHANGE

  def getDepthBeyondLocals(cb: CodeBlockSpec): Int = {
    val addr_factory = func.getProgram.getAddressFactory
    val cb_addr = addr_factory.getAddress(
      func.getEntryPoint.getAddressSpace.getSpaceID,
      cb.address
    )
    val curr_depth = cdi.getDepth(cb_addr)
    if (!validDepth(curr_depth)) {
      return 0;
    }

    val stack = func.getStackFrame()
    val max_depth = getNextLocalDepth()
    if (
      (stack.growsNegative() && curr_depth < max_depth) || (!stack
        .growsNegative() && curr_depth > max_depth)
    ) {
      (curr_depth - max_depth).abs
    } else {
      0
    }
  }

  // Determines based on stack info, a single variable representing the space beyond
  // the local variables in the stack that may currently have values
  def injectLiveLocationsAtEntry(cb: CodeBlockSpec): Option[ParamSpec] = {
    Msg.info(this, getNextLocalDepth());
    val overflow_size = getDepthBeyondLocals(cb)
    if (overflow_size > 0) {
      Some(
        ParamSpec(
          Some("overflow_stack"),
          Some(
            VarSpec(
              Seq(
                ValueSpec(
                  ValueInner.Mem(
                    MemSpec(
                      Some(
                        ProgramSpecifier.getStackRegisterName(func.getProgram())
                      ),
                      if (func.getStackFrame().growsNegative()) {
                        getNextLocalDepth() - overflow_size
                      } else { getNextLocalDepth() },
                      overflow_size
                    )
                  )
                )
              ),
              Some(Util.sizeToArray(overflow_size))
            )
          )
        )
      )
    } else {
      None
    }
  }

  def collectInjectLiveOnEntryExit(blk: CodeBlockSpec): Option[ParamSpec] = {
    val addr_factory = func.getProgram.getAddressFactory
    (blk.outgoingBlocks
      .flatMap(nd => blks.get(nd)) :+ blk)
      .maxByOption(blk =>
        cdi.getDepth(
          addr_factory.getAddress(
            func.getEntryPoint.getAddressSpace.getSpaceID,
            blk.address
          )
        )
      )(
        if (func.getStackFrame().growsNegative()) then Ordering[Int].reverse
        else Ordering[Int]
      )
      .flatMap(nd => injectLiveLocationsAtEntry(nd))
  }

  def hasStackBeyondLocalsAtEntry(blk: CodeBlockSpec): Boolean = {
    getDepthBeyondLocals(blk) > 0
  }

  def hasStackBeyondLocalsAtExit(blk: CodeBlockSpec): Boolean =
    blk.outgoingBlocks
      .flatMap(nd => blks.get(nd))
      .exists(nd => getDepthBeyondLocals(nd) > 0)

  def getBlockLiveness(): Map[CodeBlockSpec, BlockLiveness] = {
    val cfg = ComputeNodeContext.func_to_cfg(func)
    val bb_model = new BasicBlockModel(prog)
    val liveness = analyzeLiveness(cfg)
    blks.map((_, blk) => {
      val gaddr =
        prog.getAddressFactory.getDefaultAddressSpace.getAddress(blk.address)
      val blk_end = prog.getAddressFactory.getDefaultAddressSpace
        .getAddress(
          blk.address + blk.size - 1
        )
      val blk_addrs = new AddressSet(gaddr, blk_end)
      val addr_in_blk = (addr: Address) => blk_addrs.contains(addr)
      val blk_nodes = cfg.nodes
        .filter(x => addr_in_blk(x.outer.getAddress))
      val exit_nodes = blk_nodes
        .filter(x => {
          x.diSuccessors.isEmpty || x.diSuccessors
            .exists(y => !addr_in_blk(y.outer.getAddress))
        })
      val live_past_stack = collectInjectLiveOnEntryExit(blk)
      // Lookup liveness for each exit node and combine them
      val live_on_exit: LiveAddresses = exit_nodes
        .map(x => {
          if (x.diSuccessors.isEmpty)
            get_initial_after_liveness(x.outer.getAddress)
          else
            x.diSuccessors
              .filter(y => !addr_in_blk(y.outer.getAddress))
              .map(liveness(_))
              .foldLeft(LiveAddresses.empty)((acc, x) => acc.join(x))
        })
        .foldLeft(LiveAddresses.empty)((acc, x) => acc.join(x))
      val live_on_entry: LiveAddresses = {
        // Lookup liveness for the first pcode op
        // Skip any instructions that are in delay slots.
        var first_ins = prog.getListing.getInstructionAt(gaddr)
        while (first_ins != null && first_ins.isInDelaySlot) {
          first_ins = first_ins.getNext
        }
        if (first_ins != null && addr_in_blk(first_ins.getAddress())) {
          liveness(InstructionEntry(first_ins))
        } else {
          // If the entire block is nops or is in a delay slot, nothing needs to be live.
          // The live at exit calculation will do the right thing too.
          LiveAddresses.empty
        }
      }
      (
        blk,
        BlockLiveness(
          params_from_live(live_on_entry) ++ (if (hasStackBeyondLocalsAtEntry(
                                                  blk
                                                ))
                                              then live_past_stack
                                              else Set()),
          params_from_live(live_on_exit) ++ (if (hasStackBeyondLocalsAtExit(
                                                 blk
                                               ))
                                             then live_past_stack
                                             else Set())
        )
      )
    })
  }

  import LivenessAnalysis.given

  def analyzeLiveness(
      cfg: ComputeNodeContext.CFG
  ): Solution[CfgNode, LivenessAnalysis.D] = {
    val entry_states = get_liveness_entrypoints(cfg)
    implicit val res: PcodeFixpoint[LivenessAnalysis.D] = this
    ComputeNodeContext
      .reverse_node_fixpoint[LivenessAnalysis.D](cfg, entry_states)
  }

  override def update_guard(
      vnode: ghidra.program.model.pcode.Varnode,
      taken: Boolean,
      pred: LivenessAnalysis.D
  ): LivenessAnalysis.D = pred

  override def update_op(
      op: ghidra.program.model.pcode.PcodeOp,
      pred: LivenessAnalysis.D
  ): LivenessAnalysis.D =
    transfer(getInstruction(op).get, op, pred)
}
