(* -------------------------------------------------------------------- *)
(* BLS-Threshold -- Class N4: DKG / refresh public-key preservation     *)
(* -------------------------------------------------------------------- *)
(* STATUS: SHELL.                                                       *)
(*                                                                      *)
(* Claim                                                                *)
(* -----                                                                *)
(*   The Lux BLS profile's trusted-dealer keygen produces shares of    *)
(*   a master scalar; any future DKG (publicly verifiable, e.g.,        *)
(*   Pedersen-VSS over BLS12-381) that produces the same f(0) would    *)
(*   yield the same group public key derive_pk(f(0)) = g1^{f(0)}.      *)
(*                                                                      *)
(*   The Lux profile DOES NOT yet ship a DKG (only trusted-dealer);    *)
(*   the DKG gate is in SUBMISSION-STATUS.md §3.3. This file states    *)
(*   the preservation theorem statement so the future DKG land can     *)
(*   plug straight in.                                                  *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool DInterval SmtMap.
require import BLS_Threshold_N1.

type committee_t.
type refresh_transcript_t.

op derive_pk : share_t -> group_pk_t.
op group_zero_pk : group_pk_t.
op group_pk_add : group_pk_t -> group_pk_t -> group_pk_t.

(* derive_pk = G1 scalar multiplication by the secret (BLS12-381 G1). *)
axiom derive_pk_def :
  forall (s : share_t),
    derive_pk s = g1_scalar_mul s g1_gen.

op zip_add (l1 l2 : share_t list) : share_t list =
  map (fun (p : share_t * share_t) => scalar_add p.`1 p.`2) (zip l1 l2).

op fresh_sharing (Q : int list) (s : share_t) : share_t list =
  List.map (poly_eval s) Q.

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

(* G1 scalar-multiplication linearity (mirrors the G2 version in      *)
(* BLS_Threshold_N1.ec).                                                *)
axiom g1_scalar_mul_distributes :
  forall (a b : scalar_t),
    g1_add (g1_scalar_mul a g1_gen) (g1_scalar_mul b g1_gen) =
      g1_scalar_mul (scalar_add a b) g1_gen.

axiom g1_scalar_mul_zero :
  g1_scalar_mul scalar_zero g1_gen = group_zero_pk.

(* derive_pk homomorphism derived from g1_scalar_mul_distributes +     *)
(* derive_pk_def. Stated as an axiom here for symmetry with FROST_N4 / *)
(* CGGMP21_N4; provable directly.                                      *)
axiom derive_pk_homomorphism :
  forall (s1 s2 : share_t),
    derive_pk (scalar_add s1 s2) = group_pk_add (derive_pk s1) (derive_pk s2).

axiom derive_pk_zero :
  derive_pk scalar_zero = group_zero_pk.

module type BLS_Refresh = {
  proc refresh(committee : committee_t,
               old_shares : share_t list,
               transcript : refresh_transcript_t) : share_t list
}.

module BLS_Refresh_Honest : BLS_Refresh = {
  proc refresh(committee : committee_t,
               old_shares : share_t list,
               transcript : refresh_transcript_t) : share_t list = {
    var zero_sharing : share_t list;
    zero_sharing <- fresh_sharing (map (fun _ => 0) old_shares) scalar_zero;
    return zip_add old_shares zero_sharing;
  }
}.

lemma bls_threshold_n4_pk_preservation_honest :
  forall (Q : int list) (shares : share_t list),
    uniq Q => 1 <= size Q => size shares = size Q =>
    derive_pk (reconstruct Q (zip_add shares (fresh_sharing Q scalar_zero))) =
    derive_pk (reconstruct Q shares).
proof.
  move=> Q shares uQ szQ szs.
  rewrite reconstruct_linear_N4 //=; first by rewrite fresh_sharing_size.
  rewrite (shamir_correct_N4 Q scalar_zero uQ szQ).
  rewrite derive_pk_homomorphism derive_pk_zero.
  (* Same one-line group-identity admit as FROST_N4 / CGGMP21_N4 /     *)
  (* Pulsar_N4. Closure: Crypto.BLS.Threshold.group_pk_identity Lean   *)
  (* lemma.                                                             *)
  admit.
qed.

(* -------------------------------------------------------------------- *)
(* End of BLS_Threshold_N4.ec                                            *)
(* -------------------------------------------------------------------- *)
