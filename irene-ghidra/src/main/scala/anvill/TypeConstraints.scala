package anvill

import anvill.Util.ProgramAnalysisUtilMixin
import ghidra.program.model.address.{Address, AddressSetView}
import ghidra.program.model.data.{
  AbstractIntegerDataType,
  DataType,
  IntegerDataType
}
import ghidra.program.model.listing.{
  Instruction,
  Parameter,
  Program,
  VariableStorage,
  Function as GFunction
}
import ghidra.program.model.pcode.{PcodeOp, Varnode}
import cats.{Applicative, Monad}
import cats.syntax.all.*
import cats.data.Writer

import scala.jdk.CollectionConverters.*

/*
   These type constraints reflect the structure of those in "Polymorphic Type Inference for Machine Code"

   Base type variables represent terms that have types (ie Op is the type of the output of that op, Entry reg is the type
   of that reg on entry, Abstract stack represents the type of the stack etc.)

   Derived type variables represent a type with some capabilities ie. x.load is the type representing some value loaded from
   x.

   A SubtypingConstraint relates two derived type variables saying lhs.a <= rhs.b

   AddCons are special type constraints with special rules for applying specific rules related to whether an add results
   in and takes pointers or integers
   AddCons(x,y,z) says the dtv z represents the result of adding x and y. The actual typing rules for Add can be found
   in the paper "Polymorphic Type Inference for Machine Code" Appendix A.6.
 */

sealed trait TypeVariable

given Conversion[TypeVariable, DerivedTypeVariable] with
  def apply(x: TypeVariable): DerivedTypeVariable =
    DerivedTypeVariable(x, List())

case class TypeAtom(dataType: DataType) extends TypeVariable

case object AbstractStack extends TypeVariable

// A procedure has an optional callsite tag for polymorphism. a formal does not have a tag
case class TaggedProcedure(func: GFunction, callsite: Option[PcodeOp])
    extends TypeVariable:
  val is_formal: Boolean = callsite.isEmpty
end TaggedProcedure

case class Op(op: ComparablePcodeOp) extends TypeVariable {
  override def toString: String = {
    s"Op(${op.getSeqnum}: $op)"
  }
}

case class EntryRegValue(r: Varnode) extends TypeVariable

case class GlobalVariable(addr: Address) extends TypeVariable

case class Tmp(id: Int) extends TypeVariable

abstract class FieldLabel

case object Load extends FieldLabel

case class Field(offset_bytes: ByteSize, sz_bits: BitSize) extends FieldLabel

case object Store extends FieldLabel

case class InParam(ind: Int) extends FieldLabel

case class OutParam(ind: Int) extends FieldLabel

case class AddConst(ind: Long) extends FieldLabel

case class DerivedTypeVariable(base: TypeVariable, labels: List[FieldLabel]) {
  def add(nlabels: List[FieldLabel]): DerivedTypeVariable = {
    DerivedTypeVariable(base, labels ++ nlabels)
  }
}

sealed trait TypeConstraint
/*
 lhs <= rhs
 */
case class SubTypeConstraint(
    lhs: DerivedTypeVariable,
    rhs: DerivedTypeVariable
) extends TypeConstraint

case class AddCons(
    lhs: DerivedTypeVariable,
    rhs: DerivedTypeVariable,
    repr: DerivedTypeVariable
) extends TypeConstraint

abstract class Size

case class ByteSize(value: Int) extends Size
given Conversion[ByteSize, BitSize] with
  def apply(x: ByteSize): BitSize = BitSize(x.value * 8)

case class BitSize(value: Int) extends Size

case class TypeVariableAccess(tv: TypeVariable, off: ByteSize)

trait LinearlyExecutable[N] {
  def execute(cont: N, pc: PcodeOp): N
}

trait RegisterContext[N] {
  def access(cont: N, vnode: Varnode): Set[TypeVariable]
}

trait PointsToContext[N] {
  def pointsTo(cont: N, vnode: Varnode, sz: ByteSize): List[TypeVariableAccess]
}

trait NodeContext[N]
    extends LinearlyExecutable[N],
      RegisterContext[N],
      PointsToContext[N] {}

type ConstrainedValue[T] = Writer[Set[TypeConstraint], T]

trait FreshVars {
  def fresh(): Tmp
}

class PcodeEvaluator[N](val cont: N)(using
    fresh: FreshVars,
    abs_interp: NodeContext[N]
) {
  def eval_var(vnode: Varnode): ConstrainedValue[DerivedTypeVariable] = {
    val defining_vars = abs_interp.access(cont, vnode)
    if (defining_vars.size == 1) {
      Writer(Set(), DerivedTypeVariable(defining_vars.head, List()))
    } else {
      val target = fresh.fresh()
      Writer(defining_vars.map(SubTypeConstraint(_, target)), target)
    }
  }

  def execute(pc: PcodeOp): PcodeEvaluator[N] = PcodeEvaluator(
    abs_interp.execute(cont, pc)
  )

  def address_repr(
      addr: Varnode,
      sz: ByteSize,
      lbl: FieldLabel,
      addr_is_subtype: Boolean
  ): ConstrainedValue[DerivedTypeVariable] = {
    val addr_tv: ConstrainedValue[DerivedTypeVariable] =
      eval_var(addr).fmap(_.add(List[FieldLabel](lbl, Field(ByteSize(0), sz))))

    addr_tv.flatMap(repr =>
      Writer
        .tell(
          abs_interp
            .pointsTo(cont, addr, sz)
            .map(acc => {
              val abs_obj =
                DerivedTypeVariable(acc.tv, List(Field(acc.off, sz)))
              if (addr_is_subtype) {
                SubTypeConstraint(repr, abs_obj)
              } else {
                SubTypeConstraint(abs_obj, repr)
              }
            })
            .toSet
        )
        .map(_ => repr)
    )
  }
}

object TypeConstraints {
  def apply[N](gfunc: GFunction, mapping: Map[CfgNode, N])(using
      nodeContext: NodeContext[N]
  ): TypeConstraints[N] =
    new TypeConstraints[N](gfunc, 0, mapping)
}

class TypeTranslator(using freshVars: FreshVars):

  def translateDty(dty: DataType): ConstrainedValue[DerivedTypeVariable] =
    // TODO(Ian): deconstruct type for precision on fields and pointers
    val repr = DerivedTypeVariable(TypeAtom(dty), List())
    Writer(Set(), repr)

end TypeTranslator

class TypeConstraints[N](
    private val gfunc: GFunction,
    private var counter: Int,
    private val mapping: Map[CfgNode, N]
)(using NodeContext[N])
    extends ProgramAnalysisUtilMixin {

  override val prog: Program = gfunc.getProgram

  given id_gen: FreshVars with
    def fresh(): Tmp = {
      counter += 1
      Tmp(counter)
    }

  def stackStorageToVariable(varstor: VariableStorage): DerivedTypeVariable =
    // Assumption here, the stack offset is always displacement from the stack register upon entry to the function.
    DerivedTypeVariable(
      AbstractStack,
      List(Field(ByteSize(varstor.getStackOffset), ByteSize(varstor.size())))
    )

  def registerToVariable(
      context: PcodeEvaluator[N],
      varstor: VariableStorage
  ): ConstrainedValue[DerivedTypeVariable] =
    context.eval_var(
      Varnode(varstor.getRegister.getAddress, varstor.getRegister.getNumBytes)
    )

  // Returns a type variable representing storage, and the dty.
  def paramConstraint(
      context: PcodeEvaluator[N],
      param: Parameter
  ): ConstrainedValue[(DerivedTypeVariable, DerivedTypeVariable)] =
    val stor = param.getVariableStorage
    val storage_var: Option[ConstrainedValue[DerivedTypeVariable]] =
      if stor.isStackStorage then
        Some(Writer(Set(), stackStorageToVariable(stor)))
      else if stor.isRegisterStorage then
        Some(registerToVariable(context, stor))
      else None

    val dty = TypeTranslator().translateDty(param.getDataType)
    storage_var
      .map(loc => {
        (loc, dty).mapN((loc_dtv, dty_dtv) => {
          (loc_dtv, dty_dtv)
        })
      })
      .getOrElse((freshTvar(), dty).mapN((_, _)))

  def inConstraints(
      in_context: PcodeEvaluator[N],
      gfunc: GFunction,
      callsite_tag: Option[PcodeOp]
  ): ConstrainedValue[Unit] =
    val base_type_variable =
      DerivedTypeVariable(TaggedProcedure(gfunc, callsite_tag), List())

    val in_cons: ConstrainedValue[Unit] =
      gfunc.getParameters.zipWithIndex.toList.foldM(())((_, param_ind) => {
        val full_param_dtv = base_type_variable.add(List(InParam(param_ind._2)))
        val repr_vars = paramConstraint(in_context, param_ind._1)
        repr_vars.flatMap((stor, dty) => {
          val constraints: Set[TypeConstraint] =
            if callsite_tag.isDefined then
              // if formal the ins are less than storage
              Set(
                SubTypeConstraint(dty, full_param_dtv),
                SubTypeConstraint(full_param_dtv, stor)
              )
            else
              Set(
                SubTypeConstraint(stor, full_param_dtv),
                SubTypeConstraint(full_param_dtv, dty)
              )
          Writer.tell(constraints)
        })
      })
    in_cons

  def outCons(
      out_context: PcodeEvaluator[N],
      gfunc: GFunction,
      callsite_tag: Option[PcodeOp]
  ): ConstrainedValue[Unit] =
    val base_type_variable =
      DerivedTypeVariable(TaggedProcedure(gfunc, callsite_tag), List())
    Option(gfunc.getReturn)
      .map(r => {
        val full_out_param_dtv = base_type_variable.add(List(OutParam(0)))
        val repr_vars = paramConstraint(out_context, r)
        repr_vars
          .flatMap((stor, dty) => {
            val constraints: Set[TypeConstraint] =
              if callsite_tag.isDefined then
                // if formal then out is greater than storage
                Set(
                  SubTypeConstraint(stor, full_out_param_dtv),
                  SubTypeConstraint(full_out_param_dtv, dty)
                )
              else
                Set(
                  SubTypeConstraint(dty, full_out_param_dtv),
                  SubTypeConstraint(full_out_param_dtv, stor)
                )
            Writer.tell(constraints)
          })
      })
      .getOrElse(Writer(Set(), ()))
  // gets constraints for a procedure if it is a formal we want:
  // dty <= in <= storage
  // storage <= out <= dty
  /// for an actual we want:
  /// storage <= in <= dty
  /// dty <= out <= storage
  def typeConstraintsForCall(
      in_context: PcodeEvaluator[N],
      out_context: PcodeEvaluator[N],
      gfunc: GFunction,
      callsite_tag: Option[PcodeOp]
  ): ConstrainedValue[Unit] = {
    val incons = inConstraints(in_context, gfunc, callsite_tag)
    val outcons = outCons(out_context, gfunc, callsite_tag)

    incons.tell(outcons.run._1)
  }

  def isConst(vnode: Varnode): Boolean = vnode.isConstant

  def isConstOne(vnode: Varnode): Boolean =
    isConst(vnode) && vnode.getOffset == 1

  def assumeWeakInteger(
      vnode: Varnode
  ): ConstrainedValue[DerivedTypeVariable] = {
    val res = id_gen.fresh()
    Writer(
      Set(
        SubTypeConstraint(
          res,
          TypeAtom(
            AbstractIntegerDataType.getUnsignedDataType(
              vnode.getSize,
              gfunc.getProgram.getDataTypeManager
            )
          )
        )
      ),
      res
    )
  }

  def freshTvar(): ConstrainedValue[DerivedTypeVariable] =
    Writer(Set.empty, id_gen.fresh())

  def evaluate(pc: PcodeOp): Set[TypeConstraint] = {
    val eval = PcodeEvaluator(mapping(pc))

    val inputs: Array[ConstrainedValue[DerivedTypeVariable]] =
      pc.getInputs.map(eval.eval_var)
    val output: Option[ConstrainedValue[DerivedTypeVariable]] =
      Option(pc.getOutput).map(eval.execute(pc).eval_var(_))

    def assign(
        lhs: ConstrainedValue[DerivedTypeVariable],
        rhs: ConstrainedValue[DerivedTypeVariable]
    ): Set[TypeConstraint] = {
      val res = (rhs, lhs).mapN(SubTypeConstraint(_, _))
      val (cons, repr) = res.run
      cons + repr
    }

    def assign_to_output(
        rhs: ConstrainedValue[DerivedTypeVariable]
    ): Set[TypeConstraint] = {
      assign(output.get, rhs)
    }

    def create_add_result(
        pc: PcodeOp,
        neg: Boolean
    ): ConstrainedValue[DerivedTypeVariable] = {
      def create_const_dtc(
          c: ConstrainedValue[DerivedTypeVariable],
          value: Long
      ): ConstrainedValue[DerivedTypeVariable] = {
        c.fmap(_.add(List(AddConst(if neg then -value else value))))
      }

      if (pc.getInput(0).isConstant && pc.getInput(1).isConstant) {
        assumeWeakInteger(pc.getOutput)
      } else if (pc.getInput(0).isConstant) {
        create_const_dtc(inputs(1), pc.getInput(1).getOffset)
      } else if (pc.getInput(1).isConstant) {
        create_const_dtc(inputs(0), pc.getInput(0).getOffset)
      } else {
        (inputs(0), inputs(1), freshTvar()).flatMapN((lhs, rhs, res) =>
          Writer(Set(AddCons(lhs, rhs, res)), res)
        )
      }
    }

    pc.getOpcode match {
      case PcodeOp.CALL =>
        val target = getUniqueCallTarget(pc)
        target
          .map(t =>
            typeConstraintsForCall(eval, eval.execute(pc), t, Some(pc)).run._1
          )
          .getOrElse(Set())
      // hack to handle situations like a = zext ptr b = trunc a...
      case PcodeOp.COPY | PcodeOp.INT_ZEXT =>
        assign_to_output(inputs(0))
      case PcodeOp.INT_MULT =>
        if (isConstOne(pc.getInput(0)) && !isConst(pc.getInput(1))) {
          assign_to_output(inputs(1))
        } else if (isConstOne(pc.getInput(1)) && !isConst(pc.getInput(0))) {
          assign_to_output(inputs(0))
        } else {
          assign_to_output(assumeWeakInteger(pc.getOutput))
        }
      case PcodeOp.INT_ADD | PcodeOp.INT_SUB =>
        assign_to_output(create_add_result(pc, pc.getOpcode == PcodeOp.INT_SUB))
      case PcodeOp.INT_SEXT =>
        assign_to_output(assumeWeakInteger(pc.getOutput))
      case PcodeOp.LOAD =>
        val access_repr = eval.address_repr(
          pc.getInput(1),
          ByteSize(pc.getOutput.getSize),
          Load,
          false
        )
        assign_to_output(access_repr)
      case PcodeOp.STORE =>
        val tostore = pc.getInput(2)
        val access_repr = eval.address_repr(
          pc.getInput(1),
          ByteSize(tostore.getSize),
          Store,
          true
        )
        assign(access_repr, inputs(2))
      // TODO(Ian): floats
      case _ =>
        if output.isDefined then assign_to_output(freshTvar()) else Set.empty
    }

  }

  def produceEntryConstraints(): List[TypeConstraint] =
    val func_insns: java.util.Iterator[Instruction] = gfunc.getProgram
      .getListing()
      .getInstructions(gfunc.getBody, true)
    Option(gfunc.getProgram.getListing.getInstructionAt(gfunc.getEntryPoint))
      .flatMap(i => i.getPcode().headOption)
      .map(pc => PcodeEvaluator(mapping(pc)))
      .toList
      .flatMap(cont => {
        inConstraints(cont, gfunc, None).run._1.toList
      }) ++ func_insns.asScala
      .flatMap(i => i.getPcode())
      .filter(p => p.getOpcode == PcodeOp.RETURN)
      .flatMap(r => {
        outCons(PcodeEvaluator(mapping(r)), gfunc, None).run._1
      })

  def produceConstraints(): List[TypeConstraint] =
    produceConstraintsFromAddrRange(gfunc.getBody) ++ produceEntryConstraints()

  def produceConstraintsFromAddrRange(
      addrset: AddressSetView
  ): List[TypeConstraint] = {
    IteratorHasAsScala(
      gfunc.getProgram.getListing
        .getInstructions(addrset, true)
    ).asScala.flatMap(_.getPcode).flatMap(evaluate).toList

  }
}
