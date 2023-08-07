package anvill

import cats.{Applicative, Monad}

import scala.annotation.tailrec
import cats.syntax.all.*

/*
For a JoinSemiLattice creates a complete lattice by adding a top element.
 */

sealed trait CompleteLifting[+D] {
  def get(): D = {
    this match {
      case Elem(el) => el
      case _        => throw new NoSuchElementException()
    }
  }

  def isDefined: Boolean =
    this match {
      case Elem(_) => true
      case _       => false
    }
}

case class Elem[D](el: D) extends CompleteLifting[D]
case class Top[D]() extends CompleteLifting[D]

given app_lifting: Applicative[CompleteLifting] with
  override def pure[A](x: A): CompleteLifting[A] = Elem(x)

  override def ap[A, B](
      ff: CompleteLifting[A => B]
  )(fa: CompleteLifting[A]): CompleteLifting[B] =
    (ff, fa) match {
      case (Top(), _)             => Top()
      case (_, Top())             => Top()
      case (Elem(ffe), Elem(fae)) => Elem(ffe(fae))
    }

// basically just the option monad
given Monad[CompleteLifting] with
  override def pure[A](a: A): CompleteLifting[A] = app_lifting.pure(a)

  override def flatMap[A, B](
      fa: CompleteLifting[A]
  )(f: A => CompleteLifting[B]): CompleteLifting[B] = {
    val mapped: anvill.CompleteLifting[CompleteLifting[B]] =
      app_lifting.map(fa)(f)
    mapped match {
      case Top()    => Top()
      case Elem(el) => el
    }
  }

  @tailrec
  final override def tailRecM[A, B](
      a: A
  )(f: A => CompleteLifting[Either[A, B]]): CompleteLifting[B] =
    f(a) match {
      case Top()             => Top()
      case Elem(Left(nxt))   => tailRecM(nxt)(f)
      case Elem(Right(done)) => Elem(done)
    }

// TODO(Ian): this is kinda ugly... we need to let the inner type return top monadically, is there a non silly
// way to do this
trait WidenCompletedDom[D] {
  def step(prev: D, curr: D, step: Long): CompleteLifting[D]
}

object CompleteLifting {

  given [D](using wd: WidenCompletedDom[D]): Widen[CompleteLifting[D]] with
    override def step(
        prev: CompleteLifting[D],
        curr: CompleteLifting[D],
        curr_step: Long
    ): CompleteLifting[D] =
      (prev, curr).flatMapN(wd.step(_, _, curr_step))

  given [D](using lat: JoinSemiLattice[D]): CompleteLattice[CompleteLifting[D]]
    with
    val top: CompleteLifting[D] = Top()
    val bot: CompleteLifting[D] = Elem(lat.bot)

    def join(
        lhs: CompleteLifting[D],
        rhs: CompleteLifting[D]
    ): CompleteLifting[D] =
      (lhs, rhs) match {
        case (Elem(lel), Elem(rel)) => Elem(lat.join(lel, rel))
        case _                      => top
      }

    def lteq(
        x: anvill.CompleteLifting[D],
        y: anvill.CompleteLifting[D]
    ): Boolean =
      (x, y) match {
        case (_, Top())           => true
        case (Top(), _)           => false
        case (Elem(xe), Elem(ye)) => lat.lteq(xe, ye)
      }

    def tryCompare(
        x: anvill.CompleteLifting[D],
        y: anvill.CompleteLifting[D]
    ): Option[Int] =
      (x, y) match {
        case (Top(), Top())       => Some(0)
        case (Top(), _)           => Some(1)
        case (_, Top())           => Some(-1)
        case (Elem(xe), Elem(ye)) => lat.tryCompare(xe, ye)
      }
}
