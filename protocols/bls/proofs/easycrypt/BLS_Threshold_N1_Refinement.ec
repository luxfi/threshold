(* -------------------------------------------------------------------- *)
(* BLS-Threshold -- Per-party sign + Lagrange-aggregate refinement      *)
(* -------------------------------------------------------------------- *)
(* STATUS: SHELL.                                                       *)
(*                                                                      *)
(* This file states the procedure-level refinement obligations between *)
(* the abstract BLS_Threshold module type and a concrete extraction    *)
(* (the Go reference at `~/work/lux/threshold/protocols/bls/bls.go`).  *)
(*                                                                      *)
(* The refinement is SIMPLER than FROST or CGGMP21 because:             *)
(*   - There is no per-party nonce sampling (BLS partial sigs are      *)
(*     deterministic functions of (share, msg)).                        *)
(*   - There is no MtA / ZK / Paillier machinery.                       *)
(*   - The aggregate step is a pure G2 weighted sum.                    *)
(*                                                                      *)
(* The byte-walk obligation is exactly the IETF draft encoding of a    *)
(* compressed G2 point (96 bytes). Cited inline.                        *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool DInterval SmtMap.
require import BLS_Threshold_N1.

(* -------------------------------------------------------------------- *)
(* Per-party sign refinement obligation                                  *)
(* -------------------------------------------------------------------- *)
(* The honest partial_sign procedure produces sigma_i = H(m)^{s_i}.     *)

module BLS_PartialSign_Spec = {
  proc partial_sign(share : share_t, msg : message_t) : sig_share_t = {
    var sigma : g2_t;
    sigma <- g2_scalar_mul share (hash_to_g2 msg);
    return sigma;
  }
}.

(* Refinement: the concrete BLSThresholdRef.partial_sign equals the     *)
(* abstract spec by definition (both unfold to the same operator).     *)
lemma partial_sign_refinement :
    equiv [ BLSThresholdRef.partial_sign ~ BLS_PartialSign_Spec.partial_sign :
              ={share, msg}
            ==>
              ={res} ].
proof.
  proc; auto => />.
qed.

(* -------------------------------------------------------------------- *)
(* Aggregate refinement obligation                                       *)
(* -------------------------------------------------------------------- *)
(* The honest aggregate procedure produces                              *)
(*   encode_g2 (sum_{i in Q} lambda_i * sigma_i).                       *)

op aggregate_g2 (Q : int list) (sigs : g2_t list) : g2_t.

axiom aggregate_g2_spec :
  forall (Q : int list) (sigs : g2_t list),
    size Q = size sigs =>
    aggregate_g2 Q sigs =
      foldr g2_add (g2_scalar_mul scalar_zero g2_gen)
        (map (fun (p : int * g2_t) =>
                g2_scalar_mul (lagrange Q p.`1) p.`2)
             (zip Q sigs)).

module BLS_Aggregate_Spec = {
  proc aggregate(Q : int list, shares : (int * sig_share_t) list,
                 msg : message_t) : signature_t = {
    var sum_g2 : g2_t;
    sum_g2 <- aggregate_g2 Q (map snd shares);
    return encode_g2 sum_g2;
  }
}.

(* Refinement: the concrete BLSThresholdRef.aggregate equals the        *)
(* abstract spec under the aggregate_g2 unfolding.                      *)
axiom aggregate_refinement_axiom :
    equiv [ BLSThresholdRef.aggregate ~ BLS_Aggregate_Spec.aggregate :
              ={Q, shares, msg}
              /\ size Q{1} = size shares{1}
            ==>
              ={res} ].

(* -------------------------------------------------------------------- *)
(* End of BLS_Threshold_N1_Refinement.ec                                 *)
(* -------------------------------------------------------------------- *)
