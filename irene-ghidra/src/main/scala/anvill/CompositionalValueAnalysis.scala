package anvill

import ghidra.program.model.block.CodeBlock

import ghidra.program.model.listing

import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.listing.Variable
import scala.collection.immutable.TreeMap
import ghidra.program.model.pcode.Varnode

sealed abstract class ALoc
case class Reg(val reg: ghidra.program.model.lang.Register) extends ALoc
case class StackVar(val offset: Int) extends ALoc

sealed abstract class BaseVal

case class Parameter(val ind: Int) extends BaseVal
case class Register(val name: ghidra.program.model.lang.Register)
    extends BaseVal

sealed abstract class DomainValue
case class RegOff(
    val base: BaseVal,
    val offset: SignAgnosticStridedInterval
) extends DomainValue
case class Global(val offset: SignAgnosticStridedInterval) extends DomainValue
object DomValBot extends DomainValue
// For tracking non local addresses so that we do not need to blow away local A-Locs
object GlobalConst extends DomainValue
object DomValTop extends DomainValue

object DomainValue extends JoinSemiLatice[DomainValue] {

  override def tryCompare(x: DomainValue, y: DomainValue): Option[Int] = {
    if lteq(x, y) && lteq(y, x) then Some(0)
    else if lteq(x, y) then Some(1)
    else if lteq(y, x) then Some(-1)
    else None
  }

  override def lteq(x: DomainValue, y: DomainValue): Boolean = {
    (x, y) match {
      case (DomValTop, DomValTop)   => true
      case (DomValTop, _)           => false
      case (DomValBot, _)           => true
      case (Global(_), GlobalConst) => true
      case (Global(x), Global(y))   => SignAgnosticStridedInterval.lteq(x, y)
      case (RegOff(x_base, x_off), RegOff(y_base, y_off)) if x_base == y_base =>
        SignAgnosticStridedInterval.lteq(x_off, y_off)
      case (_, _) => false
    }
  }

  override def join(lhs: DomainValue, rhs: DomainValue): DomainValue =
    (lhs, rhs) match {
      case (DomValBot, x) => x
      case (x, DomValBot) => x
      case (DomValTop, _) => DomValTop
      case (_, DomValTop) => DomValTop
      case (Global(x), Global(y)) =>
        Global(SignAgnosticStridedInterval.join(x, y))
      case (Global(_), GlobalConst)   => GlobalConst
      case (GlobalConst, Global(_))   => GlobalConst
      case (GlobalConst, GlobalConst) => GlobalConst
      case (_, _)                     => DomValTop
    }

  override val bot: DomainValue = DomValBot

}

type DomType = Map[ALoc, DomainValue]

object Dom extends MappingDomain[ALoc, DomainValue](DomainValue)

class MappingDomain[K, V](po: JoinSemiLatice[V])
    extends JoinSemiLatice[Map[K, V]] {

  override def join(
      lhs: Map[K, V],
      rhs: Map[K, V]
  ): Map[K, V] =
    lhs
      .foldLeft(rhs)((agg, k_v) =>
        agg.updated(k_v(0), po.join(k_v(1), rhs(k_v(0))))
      )
      .withDefaultValue(po.bot)

  override def lteq(x: Map[K, V], y: Map[K, V]): Boolean =
    (x.keys ++ y.keys).forall(k => po.lteq(x(k), y(k)))

  override def tryCompare(x: Map[K, V], y: Map[K, V]): Option[Int] =
    (x.keys ++ y.keys).foldLeft(Option(0))((curr, k) => {
      val xv = x(k)
      val yv = y(k)
      (curr, po.tryCompare(xv, yv)) match {
        case (None, _)                    => None
        case (_, None)                    => None
        case (Some(0), Some(0))           => Some(0)
        case (Some(x), Some(y)) if x == y => Some(x)
        case (Some(_), Some(_))           => None
      }
    })

  override val bot: Map[K, V] = Map().withDefaultValue(po.bot)
}

/** A compositional value analysis based on "Efficient Fine-Grained Binary
  * Instrumentation with Applications to Taint-Tracking"
  *
  * The basic idea is to express values in a domain of input registers, stack
  * values + an offset interval
  *
  * The domain of analysis is a mapping domain from a-loc -> symm + ESI
  */
class CompositionalValueAnalysis(
    val function: ghidra.program.model.listing.Function
) extends PcodeOpTransferFunction[DomType] {

  val stack_offset_to_size: TreeMap[Int, Int] =
    (TreeMap() ++
      function
        .getAllVariables()
        .filter(v => v.isStackVariable())
        .map(v => (v.getStackOffset(), v.getLength()))
        .toSeq)

  def generate_value(vstorage: Variable): DomainValue = {
    val zero_vec = BitVector(BigInt(0), vstorage.getLength())
    val zero_sasi = SASIValue(BigInt(1), zero_vec, zero_vec)
    if (vstorage.isInstanceOf[ghidra.program.model.listing.Parameter]) {
      RegOff(
        Parameter(
          vstorage
            .asInstanceOf[ghidra.program.model.listing.Parameter]
            .getOrdinal()
        ),
        zero_sasi
      )
    } else if (vstorage.isRegisterVariable()) {
      RegOff(Register(vstorage.getRegister()), zero_sasi)
    } else {
      DomValBot
    }
  }

  def generate_aloc(vstorage: Variable): Option[ALoc] = {
    if vstorage.getVariableStorage().isCompoundStorage() then None
    else if vstorage.isStackVariable() then
      Some(
        StackVar(vstorage.getStackOffset())
      )
    else if vstorage.isRegisterVariable() then {
      val reg = vstorage.getRegister().getParentRegister()

      Some(
        Reg(reg)
      )
    } else None
  }

  def set_initial_values(
      func: ghidra.program.model.listing.Function,
      prev: DomType
  ): DomType = {
    func
      .getAllVariables()
      .foldLeft(prev)((curr, param) =>
        (for {
          aloc <- generate_aloc(param)
        } yield (aloc, generate_value(param)))
          .map((k, v) => curr.updated(k, v))
          .getOrElse(curr)
      )
  }

  def execute_block_entrance(
      func: ghidra.program.model.listing.Function,
      curr_blk: CodeBlock,
      prev: DomType
  ): DomType = {
    if (curr_blk.getFirstStartAddress() == func.getEntryPoint()) {
      set_initial_values(func, prev)
    } else {
      prev
    }
  }

  // the only static aloc that is not a computed pointer
  // for now are registers since we dont track memory
  def find_aloc(vnode: Varnode): Option[ALoc] = {
    Option(
      function
        .getProgram()
        .getLanguage()
        .getRegister(vnode.getAddress(), vnode.getSize())
    ).map(r => Reg(r.getParentRegister()))
  }

  def assign_value(
      output_vnode: Varnode,
      value: DomainValue,
      prev_dom: DomType
  ): DomType = {
    find_aloc(output_vnode)
      .map(aloc => prev_dom.updated(aloc, value))
      .getOrElse(prev_dom)
  }

  // TODO(Ian): handle uniques
  def get_vnode_value(vnode: Varnode, cur: DomType): DomainValue = {
    find_aloc(vnode).map(aloc => cur.get(aloc).get).getOrElse(DomainValue.bot)
  }

  def 

  override def execute_pcode(
      f: listing.Function,
      pc: PcodeOp,
      curr: DomType
  ): DomType = {
    pc.getOpcode() match {
      case PcodeOp.COPY =>
        assign_value(
          pc.getOutput(),
          get_vnode_value(pc.getInput(0), curr),
          curr
        )

      case PcodeOp.STORE => // now for the tricky bit


    }
  }

  override def step(
      f: listing.Function,
      i: Int,
      updating_blk: CodeBlock,
      prev: DomType,
      next: DomType
  ): DomType = ???

}
