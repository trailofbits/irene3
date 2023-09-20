package anvill

import java.util as ju
import scala.collection.mutable
import ghidra.program.model.address.{Address, AddressSet}
import ghidra.program.model.block.CodeBlock
import ghidra.program.model.lang.Register

import scala.collection.mutable.Stack
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.listing.{Instruction, Program, Variable}

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
import Util.registerToVariable

import scala.collection.immutable.Set
import scala.collection.Set as MutableSet
import ProgramSpecifier.getRegisterName
import anvill.Fixpoint.Solution
import ghidra.program.model.pcode.Varnode
import ghidra.program.model.lang.Register
import specification.specification.TypeSpec
import ghidra.util.task.TaskMonitor
import ghidra.util.Msg
import anvill.Util.ProgramAnalysisUtilMixin
import ghidra.program.model.block.BasicBlockModel

case class BlockLiveness(
    val live_before: Set[ParamSpec],
    val live_after: Set[ParamSpec]
)

object LivenessAnalysis {
  type D = Set[ParamSpec]

  given reaching_lat[A]: JoinSemiLattice[Set[A]] with
    override val bot: Set[A] = Set.empty

    override def join(lhs: Set[A], rhs: Set[A]): Set[A] = lhs.union(rhs)

    override def lteq(x: Set[A], y: Set[A]): Boolean = x.subsetOf(y)

    override def tryCompare(x: Set[A], y: Set[A]): Option[Int] =
      if x.equals(y) then Some(0)
      else if x.subsetOf(y) then Some(-1)
      else if y.subsetOf(x) then Some(1)
      else None
}

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

  def local_paramspecs(): Set[ParamSpec] = {
    func
      .getAllVariables()
      .toSeq
      .flatMap(v =>
        if (v.isStackVariable()) then {
          Seq(specifyVariable(v))
        } else {
          Seq.empty
        }
      )
      .toSet
  }

  // TODO(Ian) right now we gen all stack vars for any load
  // We could be missing a var for part of the stack becuase of how ghidra does locals
  // Need to conservatively split the stack, also need a backing alias analysis
  def gen_stack_vars(op: PcodeOp): Set[ParamSpec] = {
    if (op.getOpcode() == PcodeOp.LOAD) {
      local_paramspecs()
    } else { Set.empty }
  }

  // The safe assumption is we kill nothing
  def kill_stack_vars(op: PcodeOp) = {
    Set.empty
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

  def get_called_sig(insn: Instruction): Seq[Variable] = {
    getUniqueCallee(insn).map(f => f.getParameters().toSeq).getOrElse(Seq.empty)
  }

  def get_live_registers(vars: Seq[Variable]): Set[Register] = {
    vars
      .flatMap(v =>
        Option(v.getRegisters()).map(rs => rs.asScala).getOrElse(Seq.empty)
      )
      .toSet
  }

  def kill_call_live(insn: Instruction, op: PcodeOp): Set[ParamSpec] = {
    if (op.getOpcode() == PcodeOp.CALL) {
      getUniqueCallee(insn)
        .flatMap(f => Option(f.getReturn()))
        .flatMap(r => Option(r.getRegisters()).map(r => r.asScala))
        .getOrElse(Seq.empty)
        .map(registerToParam)
        .toSet
    } else {
      Set.empty
    }
  }

  def gen_call_live(insn: Instruction, op: PcodeOp): Set[ParamSpec] = {
    if (op.getOpcode() == PcodeOp.CALL) {
      // TODO(Ian): this assumes that we arent going to build up a stack parameter in a calling block
      // this requires handling stack extensions, which we dont handle... this could come up with something like int a; if (x<0) a= b else a = c; call(a)
      // A reasonable thing for a compile to do would be to either push b or c to the stack in each of those blocks.
      get_live_registers(get_called_sig(insn)).map(registerToParam).toSet
    } else {
      Set.empty
    }
  }

  def gen_registers(op: PcodeOp): Set[ParamSpec] = {
    val read_regs = op
      .getInputs()
      .map(vnode =>
        Option(lang.getRegister(vnode.getAddress(), vnode.getSize())).map(reg =>
          reg
        )
      )

    read_regs.flatten
      .map(r => registerToParam(r))
      .toSet
  }

  // TODO(Ian): Call pcodeops should kill returns
  def kill_registers(op: PcodeOp): Set[ParamSpec] = {
    val out = Option(op.getOutput())
    out
      .flatMap(vnode =>
        Option(lang.getRegister(vnode.getAddress(), vnode.getSize()))
      )
      .map(r =>
        // TODO(Ian): do this more effeciently somehow
        (Seq(r) ++ r.getChildRegisters().asScala)
          .map(r => registerToParam(r))
          .toSet
      )
      .getOrElse(Set.empty)

  }

  def gen(op: PcodeOp, insn: Instruction): Set[ParamSpec] = {
    val svars = gen_stack_vars(op)
    gen_call_live(insn, op) ++ svars ++ gen_registers(op)
  }

  def kill(op: PcodeOp, insn: Instruction): Set[ParamSpec] = {
    val killed =
      kill_registers(op) ++ kill_stack_vars(op) ++ kill_call_live(insn, op)
    killed
  }

  def transfer(
      insn: Instruction,
      n: PcodeOp,
      live_after: Set[ParamSpec]
  ): Set[ParamSpec] = {
    (live_after -- kill(n, insn)) ++ gen(n, insn)
  }

  def get_initial_after_liveness(): Set[ParamSpec] = {
    // If a block can return then the saves need to be live at that point,
    // + returns
    // Returns no longer need to be considered live with tail calling representations
    // Native returns already lift the return value
    Option(
      func
        .getCallingConvention()
    ).getOrElse(
      func.getProgram().getCompilerSpec().getDefaultCallingConvention()
    ).getUnaffectedList()
      .filter(vnode => vnode.isRegister())
      .map(r =>
        registerToParam(
          func
            .getProgram()
            .getLanguage()
            .getRegister(r.getAddress(), r.getSize())
        )
      )
      .toSet
  }

  def get_liveness_entrypoints(
      cfg: ComputeNodeContext.CFG
  ): Map[CfgNode, Set[ParamSpec]] = {
    cfg.nodes
      .filter(_.outgoing.isEmpty)
      .map(x => {
        (x.outer, get_initial_after_liveness())
      })
      .toMap
  }

  def getNextLocalDepth(): Int = {
    val stack = func.getStackFrame()
    if (stack.growsNegative()) {
      // shift by the return address location so we only include the negative portion
      return (-stack.getLocalSize()) + stack.getParameterOffset()
    } else {
      return stack.getLocalSize()
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
      val live_on_exit: Set[ParamSpec] = exit_nodes
        .map(x => {
          if (x.diSuccessors.isEmpty)
            get_initial_after_liveness()
          else
            x.diSuccessors
              .filter(y => !addr_in_blk(y.outer.getAddress))
              .map(liveness(_))
              .foldLeft(Set.empty[ParamSpec])((acc, x) => acc.union(x))
        })
        .foldLeft(Set.empty[ParamSpec])((acc, x) => acc.union(x))
      val live_on_entry = {
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
          Set.empty
        }
      }
      (
        blk,
        BlockLiveness(
          live_on_entry ++ (if (hasStackBeyondLocalsAtEntry(blk)) then
                              live_past_stack
                            else Set()),
          live_on_exit ++ (if (hasStackBeyondLocalsAtExit(blk)) then
                             live_past_stack
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
