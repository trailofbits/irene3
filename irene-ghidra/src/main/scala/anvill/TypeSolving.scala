package anvill

import cats.Order
import cats.Order.fromOrdering
import cats.collections.AvlSet
import cats.data.{State, Writer}
import cats.syntax.all.*
import ghidra.program.model.data.DataType

import scala.collection.immutable.SortedMap

// Currently implements quite naive type inference that does not reason about
// structural subtyping functions are typed with all possible parameters present
// and so are structures. This means we cant infer which fields should be present on a
// given tv etc. For the current purpose of propagating known types to loads this mostly ok
// TODO(Ian): do subtyping
// Generally the approach to solving transforms subtyping constraints of the form derived_type_variable = base_var(.field)*
// derived_type_variable <= derived_type_variable to an equality constraint with the grammar:
// type = type
// type :=
//  | fresh_type_var(int)
//  | base_type_variable(subtype_type_var)
//  | cons(type, ...)
//
// for instance a.b.c <= d.e.f becomes fresh_1 = fresh_2, fresh_1 = c(fresh_3), fresh_3 = b(base_type_variable(a))
// fresh_2 = f(fresh_4), fresh_4 = e(base_type_variable(d))

// Then we solve equality constraints via traditional unification. There is one caveat which is rowtypes for in/out parameters
// and structures. Rather than direct unification/type errors, when unifying into a set of types with a structure proper type,
// provided that there are no conflicts we reduce the type by joining the fields in the repr struct and the new struct in the set.
// Essentially this is HM(X) HM + constraint X where constraints here are row subtyping.

sealed trait ConstructedType extends Ordered[ConstructedType] {
  override def compare(that: ConstructedType): Int =
    Ordering.by(_.toString).compare(this, that)

  val is_proper_type: Boolean

  val is_null_ty: Boolean = false

}

// TODO(Ian): i feel like this implicit def probably is somewhere i just couldnt find where...
given [T](using Ordering[T]): Order[T] with
  override def compare(x: T, y: T): Int = fromOrdering.compare(x, y)

case class BaseVariable(tv: TypeVariable) extends ConstructedType {
  override val is_proper_type: Boolean = false
}
case class Ptr(typ: ConstructedType) extends ConstructedType {
  override val is_proper_type: Boolean = true
}

object Fun {
  private var curr_id = 0
  def apply(
      ins: Map[Int, ConstructedType],
      outs: Map[Int, ConstructedType]
  ): Fun =
    val res = new Fun(curr_id, ins, outs)
    curr_id += 1
    res
}

/// ids for constructed types are a hack to prevent structs and functions that are partially constructed from being
/// considered equal because we dont use fresh typevars for all possible offsets
// Funs all have the same number of arguments we only reason about the type of params
case class Fun(
    fun_id: Int,
    ins: Map[Int, ConstructedType],
    outs: Map[Int, ConstructedType]
) extends ConstructedType {
  override val is_proper_type: Boolean = true

  def join(f: Fun): Fun = {
    Fun(f.ins ++ this.ins, f.outs ++ this.outs)
  }
}

object Struct {
  private var curr_id = 0
  def apply(s: SortedMap[Int, (ConstructedType, ByteSize)]): Struct =
    val res = new Struct(curr_id, s)
    curr_id += 1
    res
}

case class Struct(
    struct_id: Int,
    s: SortedMap[Int, (ConstructedType, ByteSize)]
) extends ConstructedType {
  override val is_proper_type: Boolean = true

  private def has_intersecting_points(f: Struct): Boolean = {
    s.exists((k, _) =>
      f.s
        .maxBefore(k)
        .exists((elem_start, elem) =>
          k >= elem_start && k < (elem_start + elem._2.value)
        )
    )
  }
  def has_intersecting_field(f: Struct): Boolean = {
    has_intersecting_points(f) || f.has_intersecting_points(this)
  }

  def join(f: Struct): Option[Struct] = {
    Option.when(!has_intersecting_field(f))(Struct(s ++ f.s))
  }
}
// fields and additions are treated as uninterpreted fresh variables
case class FreshCons(id: Int) extends ConstructedType {
  override val is_proper_type: Boolean = false
}

object SolvingErrors {
  case class WatchedUnificationException(reason: EqCons)
      extends RuntimeException
}

// A bottom type
case object NullTy extends ConstructedType {
  override val is_proper_type: Boolean = false
  override val is_null_ty: Boolean = true
}

// Equality constraints with a "sense" of directionality
// Treated as equality except for in the primitive case
// wherein primitives are lhs <= rhs
case class EqCons(lhs: ConstructedType, rhs: ConstructedType)

class TypeSolution(private var sol: BiasedDisjointSets[ConstructedType]):
  private val sets = {
    val (new_st, sts) = sol.toSets
    sol = new_st
    for (st <- sts.toList) {
      println(s"set--(${st._1})")
      st._2.foreach(println(_))
      println("set--")
    }
    sts
  }

  def get_all_solutions(tv: TypeVariable): List[DataType] =
    val (new_st, mayb_repr) = sol.find(BaseVariable(tv))
    sol = new_st
    mayb_repr.toList.flatMap(repr_type => {
      val eq_types = sets
        .get(repr_type)
        .get
        .toList
      eq_types.flatMap {
        case BaseVariable(TypeAtom(dty)) => Some(dty)
        case _                           => None
      }
    })

  def get_unique_sol(tv: TypeVariable): Option[DataType] =
    val sols = get_all_solutions(tv)
    Option.when(sols.length == 1)(sols.headOption).flatten
  def get_sol(tv: TypeVariable): Option[DataType] =
    get_all_solutions(tv).headOption

end TypeSolution

object TypeSolvingContext {
  def apply(): TypeSolvingContext = new TypeSolvingContext(0)
}

class TypeSolvingContext(private var index: Int) {
  def fresh(): FreshCons = {
    index += 1
    FreshCons(index)
  }
  def unary_struct(
      sz: BitSize,
      offset: ByteSize,
      ty: ConstructedType
  ): Struct = {
    Struct(
      SortedMap.newBuilder
        .addOne((offset.value, (ty, ByteSize(sz.value / 8))))
        .result()
    )
  }

  def constraine_prev_type(
      prev_type: Writer[Set[EqCons], ConstructedType],
      makeConstraint: ConstructedType => Set[EqCons]
  ): Writer[Set[EqCons], Unit] = {
    for {
      prev <- prev_type
      res <- Writer.value(()).tell(makeConstraint(prev))
    } yield res
  }
  // Returns a list of constructed types as well as the representative type
  def construct_eq_cons(
      curr_value: Writer[Set[EqCons], ConstructedType],
      to_apply: Seq[FieldLabel]
  ): Writer[Set[EqCons], ConstructedType] = {
    if to_apply.isEmpty then curr_value
    else
      val front = to_apply.head
      val next_app = to_apply.drop(1)
      val this_type = fresh()

      def next_ty(
          mkConstraint: ConstructedType => Set[EqCons]
      ): Writer[Set[EqCons], ConstructedType] =
        construct_eq_cons(
          constraine_prev_type(curr_value, mkConstraint).map(_ => this_type),
          next_app
        )

      front match {
        case Store | Load =>
          next_ty(prev => Set(EqCons(prev, Ptr(this_type))))
        case Field(offset, sz) =>
          next_ty(prev =>
            Set(EqCons(prev, unary_struct(sz, offset, this_type)))
          )
        case AddConst(_) => next_ty(_ => Set())
        case InParam(ind) =>
          next_ty(prev =>
            Set(
              EqCons(
                prev,
                Fun(Map.newBuilder.addOne((ind, this_type)).result(), Map.empty)
              )
            )
          )
        case OutParam(ind) =>
          next_ty(prev =>
            Set(
              EqCons(
                prev,
                Fun(Map.empty, Map.newBuilder.addOne((ind, this_type)).result())
              )
            )
          )
      }
  }

  def translate_types(cons: List[SubTypeConstraint]): Set[EqCons] =
    cons
      .map(cons => {
        val lhs = construct_eq_cons(
          Writer.value(BaseVariable(cons.lhs.base)),
          cons.lhs.labels
        )
        val rhs = construct_eq_cons(
          Writer.value(BaseVariable(cons.rhs.base)),
          cons.rhs.labels
        )

        val res = (lhs, rhs).mapN((l, r) => {
          EqCons(l, r)
        })

        res.listen.map((curr_eq, next) => {
          println("For cons: " + cons)
          next.foreach(println(_))
          println("end with: " + curr_eq)
          curr_eq
        })
      })
      .foldM(Set())((tot: Set[EqCons], curr_cons) =>
        curr_cons.listen.map(log_and_value =>
          tot ++ Set(log_and_value._1) ++ log_and_value._2
        )
      )
      .run
      ._2

  def zipMap[K, V](mp: Map[K, V], mp2: Map[K, V]): List[List[V]] =
    (mp.toList ++ mp2.toList)
      .groupBy(_._1)
      .map((_, lst) => lst.map(_._2))
      .toList

  def matchUnify[K, V](
      lhs: Map[K, V],
      rhs: Map[K, V],
      f: V => ConstructedType
  ): Set[EqCons] =
    zipMap(lhs, rhs)
      .flatMap(matched_params =>
        if matched_params.length == 2 then
          List(EqCons(f(matched_params.head), f(matched_params(1))))
        else List()
      )
      .toSet

  def unify_function(lhs: Fun, rhs: Fun): Set[EqCons] =
    matchUnify(lhs.ins, rhs.ins, identity) ++ matchUnify(
      lhs.outs,
      rhs.outs,
      identity
    )

  def unify_struct(lhs: Struct, rhs: Struct): Set[EqCons] =
    // first we filter for elements that are exactly equal, the unify them, this is a bit over-permissive
    zipMap(lhs.s, rhs.s)
      .filter(_.length == 2)
      .filter(l => {
        l.head._2 == l(1)._2
      })
      .map(l => EqCons(l.head._1, l(1)._1))
      .toSet

  def find_or_insert[T](u: T): State[BiasedDisjointSets[T], T] =
    for {
      maybe_repr: Option[T] <- BiasedDisjointSets.find(u)
      res <- maybe_repr
        .map(State.pure)
        .getOrElse(for {
          st <- State.get[BiasedDisjointSets[T]]
          _ <- State.set(st + u)
        } yield u)
    } yield res

  // we need to bias towards having constructed types as the representatives of a group
  def unify_terms(u: EqCons): State[BiasedDisjointSets[ConstructedType], Unit] =
    (u.lhs, u.rhs) match {
      // base vars
      case (BaseVariable(_), _) | (FreshCons(_), _) | (_, BaseVariable(_)) |
          (_, FreshCons(_)) =>
        BiasedDisjointSets.union(u.lhs, u.rhs).map(_ => ())
      case (Ptr(_), Ptr(_)) =>
        BiasedDisjointSets.union(u.lhs, u.rhs).map(_ => ())
      case (x: Fun, y: Fun) =>
        val new_fun = x.join(y)
        for {
          st: BiasedDisjointSets[ConstructedType] <- State.get
          _ <- State.set(st + new_fun)
          _ <- BiasedDisjointSets.union(new_fun, u.lhs)
          _ <- BiasedDisjointSets.union(new_fun, u.rhs)
        } yield ()
      case (x: Struct, y: Struct) =>
        val new_struct = x.join(y)
        new_struct
          .map(s =>
            for {
              st: BiasedDisjointSets[ConstructedType] <- State.get
              _ <- State.set(st + s)
              _ <- BiasedDisjointSets.union(s, u.lhs)
              _ <- BiasedDisjointSets.union(s, u.rhs)
            } yield ()
          )
          .getOrElse(State.pure(()))

      case _ => State.pure(())
    }

  def to_unify_subterms(u: EqCons): Set[EqCons] = {
    (u.lhs, u.rhs) match {
      case (Ptr(sub1), Ptr(sub2)) =>
        Set(EqCons(sub1, sub2))
      case (x: Fun, y: Fun)       => unify_function(x, y)
      case (x: Struct, y: Struct) => unify_struct(x, y)
      case _                      => Set()
    }
  }

  def unify_cons(
      u: EqCons
  ): State[BiasedDisjointSets[ConstructedType], Unit] = {
    val x: State[BiasedDisjointSets[ConstructedType], Option[
      (ConstructedType, ConstructedType)
    ]] = for {
      lhs_r <- find_or_insert(u.lhs)
      rhs_r <- find_or_insert(u.rhs)
      tup = if lhs_r.is_proper_type then (lhs_r, rhs_r) else (rhs_r, lhs_r)
      opt = Option.when(!lhs_r.is_null_ty && lhs_r != rhs_r)(tup)
    } yield opt

    x.flatMap(opt =>
      opt
        .map((prop, not_prop) => {
          for {
            _ <- unify_terms(EqCons(prop, not_prop))
            _ <- to_unify_subterms(EqCons(prop, not_prop)).toSeq.foldM(())(
              (_, b) => unify_cons(b)
            )
          } yield ()
        })
        .getOrElse(State.pure(()))
    )
  }

  def test_constraint(
      eq_cons: EqCons,
      cons: (ConstructedType, ConstructedType)
  ): State[BiasedDisjointSets[ConstructedType], Unit] =
    State.get.flatMap(st => {
      val f1 = BiasedDisjointSets.find(cons._1)
      val f2 = BiasedDisjointSets.find(cons._1)

      (f1, f2).mapN((f1, f2) => {
        (f1, f2) match {
          case (Some(x), Some(y)) if x == y =>
            throw SolvingErrors.WatchedUnificationException(eq_cons)
          case _ => ()
        }
      })
    })

  def unify(
      cons: Seq[EqCons],
      watched: Option[(ConstructedType, ConstructedType)]
  ): BiasedDisjointSets[ConstructedType] = {
    val s: BiasedDisjointSets[ConstructedType] = BiasedDisjointSets()
    cons
      .foldM(())((_, b) =>
        val res = unify_cons(b)
        watched
          .map(watched => {
            res.flatMap(_ => test_constraint(b, watched))
          })
          .getOrElse(res)
      )
      .run(s)
      .value
      ._1
  }

  /*
  takes a pair that should not be unified, useful for debuggin because it alerts early
   */
  def debug_solve_watch_constraints(
      cons: List[TypeConstraint],
      watched: Option[(ConstructedType, ConstructedType)]
  ): TypeSolution =
    val translation = translate_types(cons.collect {
      case x: SubTypeConstraint => x
    }).toSeq
    val unified = unify(translation, watched)
    // we dont currently synthesize types, we only return a type if there is an atom unified with the target variable
    TypeSolution(unified)

  def solve(cons: List[TypeConstraint]): TypeSolution =
    debug_solve_watch_constraints(cons, None)

}
