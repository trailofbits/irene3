package anvill;

import anvill.ProgramSpecifier.specifyBlock
import anvill.ProgramSpecifier.getStackRegister
import collection.JavaConverters._
import ghidra.app.decompiler.*
import ghidra.program.model.address.Address
import ghidra.program.model.block.CodeBlock
import ghidra.program.model.lang.Register
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.SequenceNumber
import ghidra.program.model.pcode.Varnode
import ghidra.program.model.pcode.VarnodeTranslator
import ghidra.util.Msg
import scala.collection.mutable.{Map => MutableMap}
import scala.collection.mutable.{Set => MutableSet}
import specification.specification.{CodeBlock => CodeBlockSpec}

object BasicBlockSplit {

  def splitBlocks(
      func: Function,
      blks: Iterator[CodeBlock]
  ): Map[Long, CodeBlockSpec] = {
    val blk_map: MutableMap[Long, CodeBlockSpec] = MutableMap.empty

    // If we split off a prologue block, any subsequent blocks will need to have their "incoming"
    // list point to the new start address. Let's keep a map of addresses that need to be remapped.
    val blk_remap: MutableMap[Long, Long] = MutableMap.empty

    for (blk <- blks) {
      var blk_spec = specifyBlock(func, blk)
      val decomp_c = getGhidraDecompilation(func)
      // val stack_refs = computeStackReferences(blk)

      // Check whether the block has an prologue.
      if (blk.getFirstStartAddress == func.getEntryPoint) {
        val decomp_addrs = computeDecompilationMappings(decomp_c, blk)
        val maybe_prologue_exit = getPrologueExitAddr(blk, decomp_addrs)

        if (!maybe_prologue_exit.isEmpty) {
          val prologue_exit = maybe_prologue_exit.get
          Msg.info(this, s"Found a prologue exit for $func at $prologue_exit")

          // If so, emplace the prologue block.
          blk_map += (blk.getFirstStartAddress.getOffset ->
            CodeBlockSpec(
              blk_spec.address,
              "prologue_" + blk.getName,
              blk_spec.incomingBlocks,
              Array(prologue_exit.getOffset),
              (prologue_exit.getOffset - blk.getFirstStartAddress.getOffset).toInt,
              blk_spec.contextAssignments
            ),
          )

          // And create a separate block for the remainder of the instructions.
          blk_spec = CodeBlockSpec(
            prologue_exit.getOffset,
            blk_spec.name,
            Array(blk.getFirstStartAddress.getOffset),
            blk_spec.outgoingBlocks,
            (blk.getMaxAddress.getOffset - prologue_exit.getOffset).toInt + 1,
            blk_spec.contextAssignments
          )

          // Keep track of the mapping between the original start address and the new one now that
          // a prologue has been inserted before it. We'll need to know this to fix the "incoming"
          // list for any subsequent blocks.
          blk_remap += (blk.getFirstStartAddress.getOffset -> prologue_exit.getOffset)
        }
      }

      // Check whether the block has an epilogue.
      if (blk_spec.outgoingBlocks.isEmpty) {
        val decomp_addrs = computeDecompilationMappings(decomp_c, blk)
        val maybe_epilogue_entry = getEpilogueEntryAddr(blk, decomp_addrs)

        if (!maybe_epilogue_entry.isEmpty) {
          val epilogue_entry = maybe_epilogue_entry.get
          Msg.info(
            this,
            s"Found an epilogue entry for $func at $epilogue_entry"
          )

          // If so, emplace the epilogue block.
          blk_map += (epilogue_entry.getOffset ->
            CodeBlockSpec(
              epilogue_entry.getOffset,
              "epilogue_" + blk.getName,
              Array(blk.getFirstStartAddress.getOffset),
              blk_spec.outgoingBlocks,
              (blk.getMaxAddress.getOffset - epilogue_entry.getOffset).toInt + 1,
              blk_spec.contextAssignments
            ))

          // And create a separate block for the remainder of the instructions.
          blk_spec = CodeBlockSpec(
            blk_spec.address,
            blk_spec.name,
            blk_spec.incomingBlocks,
            Array(epilogue_entry.getOffset),
            (epilogue_entry.getOffset - blk_spec.address).toInt,
            blk_spec.contextAssignments
          )
        }
      }

      // Remap any incoming blocks.
      val remap_incoming_blks =
        blk_spec.incomingBlocks
          .map(i => blk_remap.getOrElse(i, i))
          .toSeq
      if (remap_incoming_blks != blk_spec.incomingBlocks) {
        blk_spec = CodeBlockSpec(
          blk_spec.address,
          blk_spec.name,
          remap_incoming_blks,
          blk_spec.outgoingBlocks,
          blk_spec.size,
          blk_spec.contextAssignments
        )
      }

      blk_map += (blk_spec.address -> blk_spec)
    }
    blk_map.toMap
  }

  def getGhidraDecompilation(func: Function): ClangTokenGroup = {
    // We use Ghidra's decompiler to detect prologue/epilogue blocks.
    // Decompile the function and get its C output ahead of time.
    val decomp_options = new DecompileOptions()
    val decomp_ifc = new DecompInterface()
    decomp_ifc.setOptions(decomp_options)
    decomp_ifc.toggleCCode(true)
    decomp_ifc.toggleSyntaxTree(true)
    if (!decomp_ifc.openProgram(func.getProgram)) {
      throw new RuntimeException(
        "Unable to initialize: " + decomp_ifc.getLastMessage
      )
    }
    val decomp_res = decomp_ifc.decompileFunction(func, 30, null)
    if (!decomp_res.decompileCompleted) {
      throw new RuntimeException(
        "Unable to decompile: " + decomp_ifc.getLastMessage
      )
    }
    decomp_res.getCCodeMarkup
  }

  def computeDecompilationMappings(
      decomp_c: ClangTokenGroup,
      blk: CodeBlock
  ): Set[Address] = {
    val decomp_addrs: MutableSet[Address] = MutableSet.empty
    computeClangNodeMappings(decomp_c, blk, decomp_addrs)
    decomp_addrs.toSet
  }

  def getPrologueExitAddr(
      block: CodeBlock,
      decomp_addrs: Set[Address]
  ): Option[Address] = {
    // Walk forwards and find the first instruction that doesn't look like it
    // belongs to an prologue.
    val prog = block.getModel.getProgram
    val iter =
      prog.getListing.getInstructions(block.getFirstStartAddress, true);
    var addr: Option[Address] = None
    while (iter.hasNext) {
      val ins = iter.next
      addr = Some(ins.getAddress)
      if (!block.contains(ins.getAddress())) {
        // If we reach the next block, the entire block is a prologue and we have nothing to do.
        return None
      }
      // NOTE(alex): We're currently leveraging Ghidra's decompiler and its provenance information
      // to figure out where the prologue boundary is. We're also keeping the hand-written Pcode
      // heuristics as it isn't clear which method is better at this point.
      //
      // val pcode = ins.getPcode
      // for (op <- pcode) {
      //   if (!matchesProloguePattern(op, prog, stack_refs)) {
      //     return addr
      //   }
      // }
      if (decomp_addrs.contains(ins.getAddress)) {
        return addr
      }
    }
    None
  }

  def getEpilogueEntryAddr(
      block: CodeBlock,
      decomp_addrs: Set[Address]
  ): Option[Address] = {
    // Walk backwards and find the first instruction that doesn't look like it
    // belongs to an epilogue.
    val prog = block.getModel.getProgram
    val iter =
      prog.getListing.getInstructions(block.getMaxAddress, false);
    var addr: Option[Address] = None
    while (iter.hasNext) {
      val ins = iter.next
      if (!block.contains(ins.getAddress())) {
        // If we reach the next block, the entire block is an epilogue and we have nothing to do.
        return None
      }
      // NOTE(alex): We're currently leveraging Ghidra's decompiler and its provenance information
      // to figure out where the epilogue boundary is. We're also keeping the hand-written Pcode
      // heuristics as it isn't clear which method is better at this point.
      //
      // val pcode = ins.getPcode
      // for (op <- pcode.reverse) {
      //   if (!matchesEpiloguePattern(op, prog, stack_refs)) {
      //     return addr
      //   }
      // }
      if (decomp_addrs.contains(ins.getAddress)) {
        return addr
      }
      addr = Some(ins.getAddress)
    }
    None
  }

  def computeClangNodeMappings(
      clang_node: ClangNode,
      blk: CodeBlock,
      decomp_addrs: MutableSet[Address]
  ): Unit = {
    // Some Clang nodes don't have any provenance information such as function parameters.
    if (clang_node.getMinAddress == null && clang_node.getMaxAddress == null) {
      return
    }
    // If there's no overlap between the block and the Clang node's mappings, don't search any child
    // nodes or statements.
    if (
      (clang_node.getMaxAddress.getOffset < blk.getFirstStartAddress.getOffset) ||
      (clang_node.getMinAddress.getOffset > blk.getMaxAddress.getOffset)
    ) {
      return
    }
    clang_node match {
      case clang_stmt: ClangStatement => {
        // HACK(alex): If the decompiler is mapping the instruction to a `return` statement,
        // this could easily be an epilogue. Therefore, we should ignore these.
        if (!clang_stmt.toString.contains("return")) {
          decomp_addrs += clang_node.getMaxAddress
        }
      }
      case clang_group: ClangTokenGroup => {
        // If it's not an exact match, we should still check children since this node could contain
        // multiple statements, one of which might match with our instruction.
        for (i <- 0 to clang_group.numChildren - 1) {
          val clang_child_node = clang_group.Child(i)
          computeClangNodeMappings(clang_child_node, blk, decomp_addrs)
        }
      }
      case _ => {}
    }
  }

  def matchesProloguePattern(
      op: PcodeOp,
      prog: Program,
      stack_refs: Map[Varnode, StackReference]
  ): Boolean = {
    isStackReference(op.getOutput, op.getSeqnum, prog, stack_refs) || isUnique(
      op.getOutput
    ) || writesToStack(op, prog, stack_refs) || isBitFlag(op.getOutput)
  }

  def matchesEpiloguePattern(
      op: PcodeOp,
      prog: Program,
      stack_refs: Map[Varnode, StackReference]
  ): Boolean = {
    isStackReference(op.getOutput, op.getSeqnum, prog, stack_refs) || isUnique(
      op.getOutput
    ) || readsFromStack(op, prog, stack_refs) || isProgramCounterMask(
      op,
      prog
    ) || isReturn(op) || isBitFlag(op.getOutput)
  }

  def computeStackReferences(blk: CodeBlock): Map[Varnode, StackReference] = {
    val stack_refs: MutableMap[Varnode, StackReference] = MutableMap()
    val prog = blk.getModel.getProgram
    val iter = prog.getListing.getInstructions(blk.getFirstStartAddress, true)
    while (iter.hasNext) {
      val ins = iter.next
      if (!blk.contains(ins.getAddress())) {
        return stack_refs.toMap
      }
      val pcode = ins.getPcode
      for (op <- pcode) {
        checkStackReference(op, prog, stack_refs)
      }
    }
    stack_refs.toMap
  }

  def isUnique(vnode: Varnode): Boolean = {
    // Assigning to uniques generally don't affect the processor state so we can just skip over
    // these when trying to find the epilogue/prologue boundaries.
    vnode != null && vnode.isUnique
  }

  def writesToStack(
      op: PcodeOp,
      prog: Program,
      stack_refs: Map[Varnode, StackReference]
  ): Boolean = {
    // If we're passing what appears to be a stack reference to `STORE` at the end of a function,
    // we're probably saving callee save registers.
    op.getOpcode == PcodeOp.STORE && op.getInputs.find(i =>
      isStackReference(i, op.getSeqnum, prog, stack_refs)
    ) != None
  }

  def readsFromStack(
      op: PcodeOp,
      prog: Program,
      stack_refs: Map[Varnode, StackReference]
  ): Boolean = {
    // If we're passing what appears to be a stack reference to `LOAD` at the end of a function,
    // we're probably restoring callee save registers.
    op.getOpcode == PcodeOp.LOAD && op.getOutput != null && op.getOutput.isRegister && op.getInputs
      .find(i => isStackReference(i, op.getSeqnum, prog, stack_refs)) != None
  }

  def isBitFlag(vnode: Varnode): Boolean = {
    // In the prologue or epilogue, we sometimes see ops involving flag bits on particular
    // registers or pseudo registers like `ISAModeSwitch` on ARM. There's no way to definitively
    // detect this since these aren't categorised in Sleigh any differently than say GPRs. One
    // giveaway is that they have usually have a size of 1.
    vnode != null && vnode.isRegister && vnode.getSize == 1
  }

  def isReturn(op: PcodeOp): Boolean = {
    // The epilogue usually ends with a `RETURN` so we should consider this part of it.
    op.getOpcode == PcodeOp.RETURN
  }

  def isProgramCounterMask(op: PcodeOp, prog: Program): Boolean = {
    // On ARM, we see this pattern in epilogues:
    //   pc = INT_AND pc, 0xfffffffe:4
    op.getOpcode == PcodeOp.INT_AND && op.getOutput == getProgramCounterVarnode(
      prog
    )
  }

  class StackReference(val vnode: Varnode, val start_seq: SequenceNumber)

  def isStackReference(
      vnode: Varnode,
      seq: SequenceNumber,
      prog: Program,
      stack_refs: Map[Varnode, StackReference]
  ): Boolean = {
    if (vnode == getStackVarnode(prog)) {
      return true
    }
    val maybe_stack_ref = stack_refs.get(vnode)
    if (maybe_stack_ref != None) {
      val stack_ref = maybe_stack_ref.get
      if (seq.compareTo(stack_ref.start_seq) >= 0) {
        return true
      }
    }
    false
  }

  def checkStackReference(
      op: PcodeOp,
      prog: Program,
      stack_refs: MutableMap[Varnode, StackReference]
  ): Boolean = {
    // Detects whether the operation is assigning a stack reference.

    // Firstly, if the node being assigned to is already identified as a stack reference, we're done
    val vnode = op.getOutput
    if (isStackReference(vnode, op.getSeqnum, prog, stack_refs.toMap)) {
      return true
    }

    // Usually a stack reference is copied from an existing stack reference or is the result of some
    // arithmetic operation involving a stack reference.
    val is_copy = op.getOpcode == PcodeOp.COPY
    val is_arithmetic =
      op.getOpcode == PcodeOp.INT_ADD ||
        op.getOpcode == PcodeOp.INT_SUB ||
        op.getOpcode == PcodeOp.INT_AND ||
        op.getOpcode == PcodeOp.INT_OR ||
        op.getOpcode == PcodeOp.INT_MULT
    if (!is_copy && !is_arithmetic) {
      return false
    }

    // If any of the operands are a stack reference, then let's consider the output to also be a
    // stack reference.
    val is_stack_ref =
      op.getInputs.find(i =>
        (isStackReference(i, op.getSeqnum, prog, stack_refs.toMap))
      ) != None
    if (is_stack_ref) {
      stack_refs += (vnode -> StackReference(vnode, op.getSeqnum))
    }
    is_stack_ref
  }

  def getStackVarnode(prog: Program): Varnode = {
    val trans = new VarnodeTranslator(prog)
    return trans.getVarnode(getStackRegister(prog))
  }

  def getProgramCounterRegister(prog: Program): Register = {
    prog.getLanguage().getProgramCounter()
  }

  def getProgramCounterVarnode(prog: Program): Varnode = {
    val trans = new VarnodeTranslator(prog)
    return trans.getVarnode(getProgramCounterRegister(prog))
  }
}
