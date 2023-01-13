package anvill

import java.util as ju
import scala.collection.mutable
import ghidra.program.model.block.CodeBlock
import ghidra.program.model.lang.Register
import scala.collection.mutable.Stack
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.listing.Instruction
import collection.JavaConverters._
import ghidra.app.cmd.function.CallDepthChangeInfo
import specification.specification.{Value => ValueSpec}
import specification.specification.{Register => RegSpec}
import specification.specification.{Variable => VarSpec}
import specification.specification.{Parameter => ParamSpec}
import specification.specification.Value.{InnerValue => ValueInner}
import ghidra.program.model.data.Structure
import Util.registerToVariable
import scala.collection.immutable.Set

import ghidra.program.model.listing.Variable
import ProgramSpecifier.getRegisterName
import ghidra.program.model.pcode.Varnode
import ghidra.program.model.lang.Register

case class BlockLiveness(
    val live_before: Set[ParamSpec],
    val live_after: Set[ParamSpec]
)

/** Reverse dataflow analysis over the CFG for register liveness
  *
  * @param control_flow_graph
  *   the control flow graph
  * @param func
  *   the function
  */
class LivenessAnalysis(
    val control_flow_graph: Util.CFG,
    val func: ghidra.program.model.listing.Function,
    val aliases: scala.collection.mutable.Map[Long, Structure]
) {

  val lang = func.getProgram().getLanguage()

  val register_to_variable: Map[Register, Variable] =
    func
      .getAllVariables()
      .filter(v => v.isRegisterVariable())
      .map(v => (v.getRegister(), v))
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

  // TODO(Ian) right now we gen all stack vars for any load
  // We could be missing a var for part of the stack becuase of how ghidra does locals
  // Need to conservatively split the stack, also need a backing alias analysis
  def gen_stack_vars(op: PcodeOp): Set[ParamSpec] = {
    if (op.getOpcode() == PcodeOp.LOAD) {
      func
        .getLocalVariables()
        .toSeq
        .flatMap(v =>
          if (v.isStackVariable()) then {
            Seq(specifyVariable(v))
          } else {
            Seq.empty
          }
        )
        .toSet
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

  def get_live_reigsters(vars: Seq[Variable]): Set[Register] = {
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
      get_live_reigsters(get_called_sig(insn)).map(registerToParam).toSet
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
    gen_call_live(insn, op) ++ gen_stack_vars(op) ++ gen_registers(op)
  }

  def kill(op: PcodeOp, insn: Instruction): Set[ParamSpec] = {
    kill_registers(op) ++ kill_stack_vars(op) ++ kill_call_live(insn, op)
  }

  def transfer(
      insn: Instruction,
      n: PcodeOp,
      live_after: Set[ParamSpec]
  ): Set[ParamSpec] = {
    (live_after -- kill(n, insn)) ++ gen(n, insn)
  }

  def get_initial_after_liveness(blk: CodeBlock): Set[ParamSpec] = {
    if (blk.getFlowType().isTerminal()) {
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
    } else {
      Set.empty
    }
  }

  def transfer_block(
      blk: CodeBlock,
      live_after: Set[ParamSpec]
  ): Set[ParamSpec] = {

    // get instructions in reverse then iterate over pcode in reverse
    val insns_reverse: ju.Iterator[Instruction] =
      func.getProgram().getListing().getInstructions(blk, false)
    insns_reverse.asScala.toSeq.foldLeft(live_after)(
      (curr_liveness, curr_insn) =>
        curr_insn
          .getPcode()
          .foldRight(curr_liveness)((pcode, liveness) =>
            transfer(curr_insn, pcode, liveness)
          )
    )
  }

  def collectLiveOnExit(
      n: CodeBlock,
      curr_liveness: scala.collection.Map[CodeBlock, Set[ParamSpec]]
  ): Set[ParamSpec] = {
    if (control_flow_graph.get(n).diSuccessors.isEmpty) {
      return get_initial_after_liveness(n)
    }

    val regs: Seq[Set[ParamSpec]] = control_flow_graph
      .get(n)
      .diSuccessors
      .toSeq
      .map(out => curr_liveness.get(out.toOuter).getOrElse(Set.empty))

    regs.fold(Set.empty)((x: Set[ParamSpec], y: Set[ParamSpec]) => x.union(y))
  }

  def getBlockLiveness(): Map[CodeBlock, BlockLiveness] = {
    val analysisRes = this.analyze()
    analysisRes.toMap.map((blk: CodeBlock, _) => {
      val live_on_exit = collectLiveOnExit(blk, analysisRes)
      (blk, BlockLiveness(transfer_block(blk, live_on_exit), live_on_exit))
    })
  }

  def analyze(): mutable.Map[CodeBlock, Set[ParamSpec]] = {
    val res: mutable.Map[CodeBlock, Set[ParamSpec]] = mutable.Map.from(
      this.control_flow_graph.nodes.map(nd => (nd.toOuter, Set.empty))
    )

    val worklist: Stack[CodeBlock] = Stack.from(
      this.control_flow_graph.nodes
        .map(nd => nd.toOuter)
    )

    while (!worklist.isEmpty) {
      val curr_block = worklist.pop()
      val curr_block_value =
        res.getOrElse(curr_block, Set.empty)

      val input = collectLiveOnExit(curr_block, res)

      val live_before_block = transfer_block(curr_block, input)

      res.addOne((curr_block, live_before_block))
      if (live_before_block != curr_block_value) {
        for (
          in_neighbor <- this.control_flow_graph.get(curr_block).diPredecessors
        ) {

          worklist.push(in_neighbor.toOuter)
        }
      }
    }

    res
  }

}
