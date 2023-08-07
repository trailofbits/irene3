package anvill

import ghidra.program.model.address.{Address, AddressSetView}
import ghidra.program.model.data.{
  AbstractIntegerDataType,
  DataType,
  IntegerDataType
}
import ghidra.program.model.listing.Function as GFunction
import ghidra.program.model.pcode.{PcodeOp, Varnode}
import cats.{Applicative, Monad}
import cats.syntax.all.*

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

case class TaggedProcedure(func: GFunction, callsite: PcodeOp)
    extends TypeVariable
case class Op(op: PcodeOp) extends TypeVariable

case class EntryRegValue(r: Varnode) extends TypeVariable

case class GlobalVariable(addr: Address) extends TypeVariable

case class Tmp(id: Int) extends TypeVariable

abstract class FieldLabel

class Load extends FieldLabel

case class Field(offset_bytes: ByteSize, sz_bits: BitSize) extends FieldLabel

class Store extends FieldLabel

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

case class ConstrainedValue[T](repr: T, constraints: Set[TypeConstraint])
given cvapp: Applicative[ConstrainedValue] with
  def pure[A](a: A): ConstrainedValue[A] = ConstrainedValue(a, Set())

  def ap[A, B](
      ff: ConstrainedValue[A => B]
  )(fa: ConstrainedValue[A]): ConstrainedValue[B] = {
    val res = ff.repr(fa.repr)
    ConstrainedValue(res, fa.constraints ++ ff.constraints)
  }

given Monad[ConstrainedValue] with

  override def pure[A](a: A): ConstrainedValue[A] = cvapp.pure(a)

  override def flatten[A](
      ffa: ConstrainedValue[ConstrainedValue[A]]
  ): ConstrainedValue[A] =
    ConstrainedValue(ffa.repr.repr, ffa.constraints ++ ffa.repr.constraints)

  override def flatMap[A, B](fa: ConstrainedValue[A])(
      f: A => ConstrainedValue[B]
  ): ConstrainedValue[B] =
    val nested: ConstrainedValue[ConstrainedValue[B]] = cvapp.map(fa)(f)
    nested.flatten

  override def tailRecM[A, B](a: A)(
      f: A => ConstrainedValue[Either[A, B]]
  ): ConstrainedValue[B] =
    val buf = List.newBuilder[TypeConstraint]
    @annotation.tailrec
    def go(currv: A): B = f(currv) match {
      case ConstrainedValue(Right(repr), constraints) =>
        buf ++= constraints
        repr
      case ConstrainedValue(Left(repr), constraints) =>
        buf ++= constraints
        go(repr)
    }
    ConstrainedValue(go(a), buf.result().toSet)
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
      ConstrainedValue(DerivedTypeVariable(defining_vars.head, List()), Set())
    } else {
      val target = fresh.fresh()
      ConstrainedValue(
        target,
        defining_vars.map(SubTypeConstraint(_, target))
      )
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

    ConstrainedValue[DerivedTypeVariable](
      addr_tv.repr,
      addr_tv.constraints ++ abs_interp
        .pointsTo(cont, addr, sz)
        .map(acc => {
          val abs_obj = DerivedTypeVariable(acc.tv, List(Field(acc.off, sz)))
          if (addr_is_subtype) {
            SubTypeConstraint(addr_tv.repr, abs_obj)
          } else {
            SubTypeConstraint(abs_obj, addr_tv.repr)
          }
        })
        .toSet
    )
  }
}

object TypeConstraints {
  def apply[N](gfunc: GFunction, mapping: Map[PcodeOp, N])(using
      nodeContext: NodeContext[N]
  ): TypeConstraints[N] =
    new TypeConstraints[N](gfunc, 0, mapping)
}

class TypeConstraints[N](
    private val gfunc: GFunction,
    private var counter: Int,
    private val mapping: Map[PcodeOp, N]
)(using NodeContext[N]) {

  given id_gen: FreshVars with
    def fresh(): Tmp = {
      counter += 1
      Tmp(counter)
    }

  def isConst(vnode: Varnode): Boolean = vnode.isConstant

  def isConstOne(vnode: Varnode): Boolean =
    isConst(vnode) && vnode.getOffset == 1

  def assumeWeakInteger(
      vnode: Varnode
  ): ConstrainedValue[DerivedTypeVariable] = {
    val res = id_gen.fresh()
    ConstrainedValue(
      res,
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
      )
    )
  }

  def freshTvar(): ConstrainedValue[DerivedTypeVariable] =
    ConstrainedValue(id_gen.fresh(), Set.empty)

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
      res.constraints + res.repr
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
          ConstrainedValue(res, Set(AddCons(lhs, rhs, res)))
        )
      }
    }

    pc.getOpcode match {
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
          Load(),
          false
        )
        assign_to_output(access_repr)
      case PcodeOp.STORE =>
        val tostore = pc.getInput(2)
        val access_repr = eval.address_repr(
          pc.getInput(1),
          ByteSize(tostore.getSize),
          Store(),
          true
        )
        assign(access_repr, inputs(2))
      // TODO(Ian): floats
      case _ =>
        if output.isDefined then assign_to_output(freshTvar()) else Set.empty
    }

  }

  def produceConstraints(): List[TypeConstraint] =
    produceConstraintsFromAddrRange(gfunc.getBody)

  def produceConstraintsFromAddrRange(
      addrset: AddressSetView
  ): List[TypeConstraint] = {
    IteratorHasAsScala(
      gfunc.getProgram.getListing
        .getInstructions(addrset, true)
    ).asScala.flatMap(_.getPcode).flatMap(evaluate).toList

  }
}
