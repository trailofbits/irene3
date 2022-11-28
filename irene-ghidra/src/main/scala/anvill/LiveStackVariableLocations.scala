// Adapted from https://github.com/trailofbits/pace-commons/blob/main/ghidra_commons/src/main/java/ghidra_commons/analysis/LiveStackVariableLocations.java

package anvill

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Variable
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Function
import collection.immutable.TreeMap
import java.{util => ju}
import collection.JavaConverters._
import ghidra.app.cmd.function.CallDepthChangeInfo
import ghidra.program.model.listing.VariableFilter

object LiveStackVariableLocations {
  def isValidStackDepthChange(stack_depth_change: Int): Boolean =
    stack_depth_change != Function.UNKNOWN_STACK_DEPTH_CHANGE && stack_depth_change != Function.INVALID_STACK_DEPTH_CHANGE

  def analyzeVariables(
      target_func: Function,
      followStackDirection: Boolean
  ): Map[Address, Set[Variable]] = {
    def stack_depth_info = new CallDepthChangeInfo(target_func)
    def live_to_stack_variable =
      target_func
        .getStackFrame()
        .getStackVariables()
        .toSeq
        .groupBy(stack_var => {
          def start_offset = stack_var.getStackOffset()
          if (
            target_func.getStackFrame().growsNegative() == followStackDirection
          ) {
            start_offset
          } else {
            start_offset + stack_var.getLength() - 1
          }
        })
        .view
        .mapValues(vars => vars.toSet)
        .to(TreeMap)

    def inst_iterator: ju.Iterator[Instruction] =
      target_func
        .getProgram()
        .getListing()
        .getInstructions(target_func.getBody(), true)

    inst_iterator.asScala.toSeq
      .groupBy(insn => insn.getAddress())
      .view
      .mapValues(insns =>
        insns
          .map(insn => {
            def prev_depth = stack_depth_info.getDepth(insn.getAddress())
            def stack_depth_change =
              stack_depth_info.getInstructionStackDepthChange(insn)
            def should_be_neg =
              followStackDirection == target_func
                .getStackFrame()
                .growsNegative()
            def is_valid_stack_depth =
              isValidStackDepthChange(stack_depth_change)
            if (
              is_valid_stack_depth && (stack_depth_change < 0 && should_be_neg || stack_depth_change > 0 && !should_be_neg)
            ) {
              if (stack_depth_change < 0) {
                live_to_stack_variable
                  .slice(prev_depth + stack_depth_change, prev_depth)
              } else {
                live_to_stack_variable
                  .slice(prev_depth + 1, prev_depth + stack_depth_change + 1)
              }
            } else {
              TreeMap[Int, Set[Variable]]()
            }
          })
          .flatMap(m => m.toSeq.map(_._2))
      )
      .mapValues(sets => sets.reduceOption((a, b) => a ++ b).getOrElse(Set()))
      .toMap
  }

  def getAllocationPoints(target_func: Function) =
    analyzeVariables(target_func, true)

  def getFreePoints(target_func: Function) =
    analyzeVariables(target_func, false)

  def getVariablesMissingFromPoints(
      target_func: Function,
      seen_points: Map[Address, Set[Variable]]
  ): Set[Variable] = {
    def seen_vars = seen_points.values.flatMap(_.toSeq).toSet
    target_func
      .getVariables(VariableFilter.STACK_VARIABLE_FILTER)
      .filter(tgt => !(seen_vars contains tgt))
      .toSet
  }
}
