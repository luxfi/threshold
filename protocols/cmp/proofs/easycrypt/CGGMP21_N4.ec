(* -------------------------------------------------------------------- *)
(* CGGMP21 -- Class N4: refresh / proactive rotation                    *)
(* -------------------------------------------------------------------- *)
(* STATUS: SHELL. Mirrors FROST_N4 and Pulsar_N4 structurally.          *)
(*                                                                      *)
(* Claim                                                                *)
(* -----                                                                *)
(*   The CGGMP21 proactive-refresh protocol (CCS '21 §7) preserves the *)
(*   group public key across share rotations. Refresh produces fresh   *)
(*   Paillier moduli + fresh Pedersen parameters + rotated Shamir      *)
(*   shares, but the underlying secret f(0) — and hence the group ECDSA*)
(*   public key g^{f(0)} — is invariant.                                *)
(*                                                                      *)
(* Reduction strategy                                                    *)
(* ------------------                                                    *)
(*   1. Shamir-zero re-randomisation: refresh adds a fresh sharing of  *)
(*      zero to the existing shares. Group structure on F_n.            *)
(*   2. derive_pk linearity: PK = g^x where x = f(0). Refresh           *)
(*      preserves f(0) by construction.                                  *)
(*   3. Auxiliary parameters (Paillier, Pedersen) are independent of   *)
(*      the secret; rotating them does not change PK.                   *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool DInterval SmtMap.
require import CGGMP21_N1.

type committee_t.
type refresh_transcript_t.

op derive_pk : share_t -> group_pk_t.
op group_zero_pk : group_pk_t.
op group_pk_add : group_pk_t -> group_pk_t -> group_pk_t.

op zip_add (l1 l2 : share_t list) : share_t list =
  map (fun (p : share_t * share_t) => scalar_add p.`1 p.`2) (zip l1 l2).

op fresh_sharing (Q : int list) (s : share_t) : share_t list =
  List.map (poly_eval s) Q.

(* BRIDGED TO LEAN — mirror of FROST_N4 axioms over F_n.                *)

axiom scalar_add_zeroR_N4 : forall (s : scalar_t), scalar_add s scalar_zero = s.

axiom reconstruct_linear_N4 :
  forall (Q : int list) (a b : share_t list),
    size a = size Q => size b = size Q =>
    reconstruct Q (zip_add a b) =
      scalar_add (reconstruct Q a) (reconstruct Q b).

axiom shamir_correct_N4 :
  forall (Q : int list) (s : share_t),
    uniq Q => 1 <= size Q =>
    reconstruct Q (fresh_sharing Q s) = s.

axiom fresh_sharing_size :
  forall (Q : int list) (s : share_t),
    size (fresh_sharing Q s) = size Q.

(* BRIDGE: derive_pk is the linear map g^s over F_n (the secp256k1     *)
(* group homomorphism). Lean: `Crypto.CGGMP21.derive_pk_homomorphism`. *)
axiom derive_pk_homomorphism :
  forall (s1 s2 : share_t),
    derive_pk (scalar_add s1 s2) = group_pk_add (derive_pk s1) (derive_pk s2).

axiom derive_pk_zero :
  derive_pk scalar_zero = group_zero_pk.

(* BRIDGE: group_zero_pk is the identity of the secp256k1 point group   *)
(* (the point at infinity); right-identity is an AddGroup instance fact  *)
(* (Mathlib `add_zero`). Same bridge as FROST_N4 / Pulsar_N4.            *)
axiom group_pk_add_zeroR :
  forall (p : group_pk_t), group_pk_add p group_zero_pk = p.

(* CGGMP21 refresh module type.                                         *)
module type CGGMP21_Refresh = {
  proc refresh(committee : committee_t,
               old_shares : share_t list,
               transcript : refresh_transcript_t) : share_t list
}.

module CGGMP21_Refresh_Honest : CGGMP21_Refresh = {
  proc refresh(committee : committee_t,
               old_shares : share_t list,
               transcript : refresh_transcript_t) : share_t list = {
    var zero_sharing : share_t list;
    zero_sharing <- fresh_sharing (map (fun _ => 0) old_shares) scalar_zero;
    return zip_add old_shares zero_sharing;
  }
}.

(* Public-key preservation theorem.                                     *)
lemma cggmp21_n4_pk_preservation_honest :
  forall (Q : int list) (shares : share_t list),
    uniq Q => 1 <= size Q => size shares = size Q =>
    derive_pk (reconstruct Q (zip_add shares (fresh_sharing Q scalar_zero))) =
    derive_pk (reconstruct Q shares).
proof.
  move=> Q shares uQ szQ szs.
  rewrite reconstruct_linear_N4 //=; first by rewrite fresh_sharing_size.
  rewrite (shamir_correct_N4 Q scalar_zero uQ szQ).
  rewrite derive_pk_homomorphism derive_pk_zero.
  (* group_pk_add p group_zero_pk = p (group right-identity).          *)
  by rewrite group_pk_add_zeroR.
qed.

(* -------------------------------------------------------------------- *)
(* End of CGGMP21_N4.ec                                                  *)
(* -------------------------------------------------------------------- *)
