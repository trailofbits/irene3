module Bignum

open FStar

type t = list bool

let interp_bit (b: bool) : x: nat{x = 0 \/ x = 1} = if b then 1 else 0

let rec interpretation_0 (a: t) (tot: int) : int =
  match a with
  | [] -> tot
  | b :: rst ->
    let v = (interp_bit b) in
    interpretation_0 rst ((op_Multiply tot 2) + v)

let interpretation (a: t) : int = interpretation_0 a 0

let () = assert (interpretation_0 [true; false; true; true; false] 0 = 22)

let rec length (#a: Type) (x: list a) : nat =
  match x with
  | [] -> 0
  | a :: rst -> 1 + length rst



(*
let equal_length_and_empty_implies_empty (#a: Type) (x y: list a)
    : Lemma (requires length x = length y /\ x = []) (ensures y = []) = ()
*)

let add_bits (x y c: bool)
    : res:
    (bool * bool)
      { let res_b, res_c = res in
        interpretation [res_b] + op_Multiply 2 (interpretation [res_c]) =
        interpretation [x] + interpretation [y] + interpretation [c] } =
  let tot = interp_bit x + interp_bit y + interp_bit c in
  match tot with
  | 0 -> (false, false)
  | 1 -> (true, false)
  | 2 -> (false, true)
  | 3 -> (true, true)

let x = fst (1, 2)

let rec add_with_carry (#n: nat) (a b: (x: t{length x = n})) : r: (t * bool){length (fst r) = n} =
  match (a, b) with
  | [], [] -> ([], false)
  | ac :: arst, bc :: brst ->
    let tot, c = add_with_carry #(length arst) arst brst in
    let added_bit, nc = add_bits ac bc c in
    (added_bit :: tot, nc)

let p = (nat ==> x: int{x >= 0})

let interpret_ac_res (x, y: (t * bool)) : int = interpretation (y :: x)

let rec pow (a: int) (k: nat) : int = if k = 0 then 1 else op_Multiply a (pow a (k - 1))

let rec new_digit_value (#n: nat) (x: bool) (lst: t{length lst = n})
    : Lemma
    (interpretation (x :: lst) = (op_Multiply (pow 2 n) (interp_bit x)) + interpretation lst) =
  admit ()

let rec added_digit (#n: nat) (x y: (x: t{Cons? x /\ length (x) = n}))
    : Lemma
    (interpretation x + interpretation y =
      interpretation (Cons?.tl x) + interpretation (Cons?.tl y) +
      (op_Multiply (pow 2 (n - 1)) (interp_bit (Cons?.hd x))) +
      (op_Multiply (pow 2 (n - 1)) (interp_bit (Cons?.hd y))) +
      (let _, c = add_with_carry #(n - 1) (Cons?.tl x) (Cons?.tl y) in
        op_Multiply (pow 2 (n - 1)) (interp_bit c))) =
  match (x, y) with
  | hx :: tx, hy :: ty -> ()
  | hx :: hhx :: tx, hy :: hhy :: ty ->
    added_digit #(n - 1) (hhx :: tx) (hhy :: ty);
    (assert ());
    ()

let rec add_with_carry_correct (#n: nat) (a b: (x: t{length x = n}))
    : Lemma
    (let res = add_with_carry #n a b in
      interpret_ac_res res = interpretation a + interpretation b) =
  match (a, b) with
  | [], [] ->
    assert (interpret_ac_res (add_with_carry #0 [] []) = 0);
    assert (interpretation a + interpretation b = 0);
    ()
  | ac :: arst, bc :: brst ->
    let x = add_with_carry #(n - 1) arst brst in
    let y = add_with_carry #n a b in
    let ntot, nc = add_bits ac bc (snd x) in
    assert (y = (ntot :: fst x, nc)); (*IH*)
    (*IH let x = add_with_carry_correct #(n - 1) arst brst in  interpretation (snd x :: fst x) = interpretation arst + interpretation rst)  *)
    add_with_carry_correct #(n - 1) arst brst;
    (assert (interpret_ac_res x = interpretation arst + interpretation brst));
    new_digit_value #(n - 1) (snd x) (fst x);
    (assert (interpret_ac_res x =
          op_Multiply (pow 2 (n - 1)) (interp_bit (snd x)) + interpretation (fst x)));
    (assert (interpretation (fst x) =
          interpretation arst + interpretation brst -
          op_Multiply (pow 2 (n - 1)) (interp_bit (snd x))));
    new_digit_value #(n - 1) ntot (fst x); (*interpretation arst + interpretation brst +   *)
    new_digit_value #n nc (ntot :: fst x);
    (assert (interpret_ac_res y =
          op_Multiply (pow 2 n) (interp_bit nc) + op_Multiply (pow 2 (n - 1)) (interp_bit ntot) +
          interpretation (fst x)));
    (assert (interpret_ac_res y =
          op_Multiply (pow 2 n) (interp_bit nc) + op_Multiply (pow 2 (n - 1)) (interp_bit ntot) +
          interpretation arst +
          interpretation brst -
          op_Multiply (pow 2 (n - 1)) (interp_bit (snd x))));
    let mul_by = op_Multiply (pow 2 (n - 1)) in
    (assert (interpret_ac_res y =
          mul_by (interp_bit ac) + mul_by (interp_bit bc) + mul_by (interp_bit (snd x)) +
          interpretation arst +
          interpretation brst));
    ()

(*
let rec add_zeros (a: t) (n: nat)
    : x: t{length (x) = length (a) + n /\ interpretation a = interpretation x} =
  if n = 0 then a else (false :: add_zeros a (n - 1))

let add (a b: t) : x: t{interpretation x = (interpretation a + interpretation b)} =
  let la = length a in
  let lb = length b in
  let an = (if la < lb then add_zeros a (lb - la) else a) in
  let bn = (if lb < la then add_zeros b (la - lb) else b) in
  let curr, c = add_with_carry #(length an) an bn in
  c :: curr*)