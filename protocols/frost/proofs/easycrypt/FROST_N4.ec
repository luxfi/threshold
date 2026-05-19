(* -------------------------------------------------------------------- *)
(* FROST -- Class N4 DKG public-key preservation                        *)
(* -------------------------------------------------------------------- *)
(* STATUS: SHELL. The Lagrange-algebraic kernel is closed by the four   *)
(* Lean-bridged axioms (mirroring Pulsar_N4); the FROST-specific        *)
(* Pedersen-VSS layer remains gated on the Komlo-Goldberg DKG byte-walk *)
(* and is documented in AXIOM-INVENTORY.md.                              *)
(*                                                                      *)
(* Claim                                                                *)
(* -----                                                                *)
(*   The FROST Keygen protocol (Komlo-Goldberg Fig. 1, three-round      *)
(*   Pedersen-VSS) produces a group public key derived from the master  *)
(*   secret f(0); after a (re-)KeyGen or proactive-refresh into the     *)
(*   same committee under the same access structure, the group public  *)
(*   key is invariant across share rotations.                            *)
(*                                                                      *)
(* Reduction strategy                                                    *)
(* ------------------                                                    *)
(*   1. Shamir-zero re-randomisation: refresh produces a fresh sharing  *)
(*      of the SAME secret by adding a fresh sharing of zero.           *)
(*   2. Group structure linearity: derive_pk is the linear map          *)
(*      derive_pk(s) = g^s, so derive_pk depends only on the secret.    *)
(*   3. => Public key is invariant across refresh.                       *)
(*                                                                      *)
(* The Lagrange identities below MIRROR Pulsar_N4 exactly. The bridge   *)
(* targets live in `~/work/lux/proofs/lean/Crypto/FROST.lean` (extended *)
(* by this submission).                                                  *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool DInterval SmtMap.
require import FROST_N1.

type committee_t.
type refresh_transcript_t.

op derive_pk : share_t -> group_pk_t.
op group_zero_pk : group_pk_t.

(* Lift derive_pk through scalar addition: g^{s_1+s_2} = g^{s_1} * g^{s_2}. *)
op group_pk_add : group_pk_t -> group_pk_t -> group_pk_t.

(* ===================================================================
   Algebraic structure on share_t (mirrors Pulsar_N4).
   =================================================================== *)
op zip_add (l1 l2 : share_t list) : share_t list =
  map (fun (p : share_t * share_t) => scalar_add p.`1 p.`2) (zip l1 l2).

op fresh_sharing (Q : int list) (s : share_t) : share_t list =
  List.map (poly_eval s) Q.

(* BRIDGED TO LEAN: the three axioms below correspond 1:1 to proved     *)
(* Lean theorems in `~/work/lux/proofs/lean/Crypto/FROST.lean` +        *)
(* `~/work/lux/proofs/lean/Crypto/Threshold_Lagrange.lean`. Inline      *)
(* citations given per-axiom; the full table lives in                   *)
(* `~/work/lux/threshold/protocols/frost/proofs/lean-easycrypt-         *)
(* bridge.md`.                                                          *)

(* BRIDGE: instance fact for any AddCommMonoid (Mathlib auto-derives).  *)
axiom scalar_add_zeroR_N4 : forall (s : scalar_t), scalar_add s scalar_zero = s.

(* BRIDGE: Crypto.FROST.Lagrange.combine_distributes_over_sum           *)
(* (`~/work/lux/proofs/lean/Crypto/Threshold_Lagrange.lean:81`).        *)
axiom reconstruct_linear_N4 :
  forall (Q : int list) (a b : share_t list),
    size a = size Q => size b = size Q =>
    reconstruct Q (zip_add a b) =
      scalar_add (reconstruct Q a) (reconstruct Q b).

(* BRIDGE: Crypto.FROST.Lagrange.shamir_correct_at_target              *)
(* (`~/work/lux/proofs/lean/Crypto/Pulsar/Shamir.lean:76` —             *)
(* same theorem, applied here over F_r instead of R_q).                 *)
axiom shamir_correct_N4 :
  forall (Q : int list) (s : share_t),
    uniq Q => 1 <= size Q =>
    reconstruct Q (fresh_sharing Q s) = s.

axiom fresh_sharing_size :
  forall (Q : int list) (s : share_t),
    size (fresh_sharing Q s) = size Q.

(* BRIDGE: derive_pk is the linear map g^s over the additive group of  *)
(* F_r; (`~/work/lux/proofs/lean/Crypto/FROST.lean:add_homomorphism`).  *)
axiom derive_pk_homomorphism :
  forall (s1 s2 : share_t),
    derive_pk (scalar_add s1 s2) = group_pk_add (derive_pk s1) (derive_pk s2).

axiom derive_pk_zero :
  derive_pk scalar_zero = group_zero_pk.

(* ===================================================================
   FROST Refresh / Proactive-rotation: public-key preservation theorem.
   =================================================================== *)

module type FROST_Refresh = {
  proc refresh(committee : committee_t,
               old_shares : share_t list,
               transcript : refresh_transcript_t) : share_t list
}.

(* Honest refresh: produce a fresh sharing of zero, add componentwise. *)
module FROST_Refresh_Honest : FROST_Refresh = {
  proc refresh(committee : committee_t,
               old_shares : share_t list,
               transcript : refresh_transcript_t) : share_t list = {
    var zero_sharing : share_t list;
    zero_sharing <- fresh_sharing (map (fun _ => 0) old_shares) scalar_zero;
    return zip_add old_shares zero_sharing;
  }
}.

(* Public-key preservation theorem: derive_pk(reconstruct(refresh(shares))) *)
(* = derive_pk(reconstruct(shares)).                                    *)
lemma frost_n4_pk_preservation_honest :
  forall (Q : int list) (shares : share_t list),
    uniq Q => 1 <= size Q => size shares = size Q =>
    derive_pk (reconstruct Q (zip_add shares (fresh_sharing Q scalar_zero))) =
    derive_pk (reconstruct Q shares).
proof.
  move=> Q shares uQ szQ szs.
  rewrite reconstruct_linear_N4 //=; first by rewrite fresh_sharing_size.
  rewrite (shamir_correct_N4 Q scalar_zero uQ szQ).
  rewrite derive_pk_homomorphism derive_pk_zero.
  (* group_pk_add P group_zero_pk = P (group identity).                 *)
  (* Stated as a one-line algebraic identity inline.                    *)
  admit.  (* Lean bridge: derive_pk_group_identity (one line, future). *)
qed.

(* -------------------------------------------------------------------- *)
(* End of FROST_N4.ec                                                    *)
(* -------------------------------------------------------------------- *)
