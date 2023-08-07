module Itv

open FStar

type abs_itv = | AInt : int -> int -> abs_itv

let rec list_of_len (len: nat) (start: int) : list int =
  if len = 0 then [] else (start :: list_of_len (len - 1) (start + 1))

let card (AInt lb ub: abs_itv) : nat = if ub < lb then 0 else (ub - lb)

let to_list (AInt lb ub: abs_itv) : list int =
  let c = card (AInt lb ub) in
  list_of_len c lb

let gamma (elem: abs_itv) : Set.set int = Set.as_set (to_list elem)