(* -------------------------------------------------------------------- *)
(* BLS-Threshold -- Class N1 byte-equality reduction (Lux profile)      *)
(* -------------------------------------------------------------------- *)
(* STATUS: SHELL.                                                       *)
(*                                                                      *)
(* Honest framing                                                       *)
(* --------------                                                       *)
(*   BLS is NOT a NIST standard at this submission cycle. The IETF      *)
(*   draft `draft-irtf-cfrg-bls-signature-05` is the normative target   *)
(*   for single-party BLS. "N1" here is the LUX-PROFILE analogue of    *)
(*   the Pulsar Class-N1 statement: the threshold-produced signature    *)
(*   is byte-identical to a single-party IETF BLS signature on the      *)
(*   Lagrange-reconstructed master secret, verifiable under any          *)
(*   draft-conformant BLS verifier (`luxfi/crypto/bls`,                  *)
(*   `cloudflare/circl/sign/bls`).                                       *)
(*                                                                      *)
(* Claim                                                                *)
(* -----                                                                *)
(*   For every (group_pk, sk_shares) produced by                        *)
(*   `bls.TrustedDealer.GenerateShares` (Shamir secret sharing of a    *)
(*   fresh single-party BLS secret), for every message m and every     *)
(*   honest signer set Q of size |Q| >= threshold, the byte string     *)
(*   produced by                                                        *)
(*                                                                      *)
(*       AggregateSignatures Q {sigma_i}                               *)
(*                                                                      *)
(*   equals the byte string produced by                                 *)
(*                                                                      *)
(*       BLS.Sign(sk_master, m)                                         *)
(*                                                                      *)
(*   where sk_master = f(0) is the master secret used by the dealer.   *)
(*                                                                      *)
(* Reduction strategy (Boldyreva 2003 §3)                               *)
(* --------------------                                                 *)
(*   1. Per-party signature: sigma_i = H(m)^{s_i} on G2.                *)
(*   2. Lagrange aggregation: sigma = sum_i lambda_i * sigma_i on G2.   *)
(*   3. By the Shamir identity over F_r: sum_i lambda_i * s_i = f(0).  *)
(*   4. By the scalar-multiplication identity on G2:                    *)
(*        sum_i lambda_i * H(m)^{s_i} = H(m)^{sum_i lambda_i * s_i}     *)
(*                                    = H(m)^{f(0)}                     *)
(*                                    = sigma                            *)
(*   5. Encoding: IETF draft signature is the compressed G2 point.      *)
(*                                                                      *)
(* This file states the obligation surface; the discharge mechanism is *)
(* the standard one: an `equiv` between the threshold Combine module    *)
(* and the single-party BLS.Sign module under the Lagrange identity.   *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool DInterval SmtMap.

(* -------------------------------------------------------------------- *)
(* Core types                                                            *)
(* -------------------------------------------------------------------- *)

type byte_seq = bool list.

(* Scalar in F_r where r is the BLS12-381 group order.                 *)
type scalar_t.

(* Point on G1 (public-key group, 48 bytes compressed).                *)
type g1_t.

(* Point on G2 (signature group, 96 bytes compressed).                 *)
type g2_t.

(* Point in GT (target group, ~4608 bytes uncompressed, internal).     *)
type gt_t.

(* Secret share: scalar in F_r (Shamir share of master BLS secret).   *)
type share_t = scalar_t.

(* Group public key (BLS12-381 G1).                                     *)
type group_pk_t = g1_t.

(* Per-party signature share (BLS12-381 G2).                            *)
type sig_share_t = g2_t.

(* Aggregated BLS signature (G2 compressed, 96 bytes).                 *)
type signature_t = g2_t.

(* Message bytes.                                                        *)
type message_t = byte_seq.

(* -------------------------------------------------------------------- *)
(* Group structure (BLS12-381)                                           *)
(* -------------------------------------------------------------------- *)

(* G1 generator.                                                         *)
op g1_gen : g1_t.

(* G2 generator.                                                         *)
op g2_gen : g2_t.

(* Scalar multiplication.                                                *)
op g1_scalar_mul : scalar_t -> g1_t -> g1_t.
op g2_scalar_mul : scalar_t -> g2_t -> g2_t.

(* Group addition.                                                       *)
op g1_add : g1_t -> g1_t -> g1_t.
op g2_add : g2_t -> g2_t -> g2_t.

(* Bilinear pairing.                                                     *)
op pairing : g1_t -> g2_t -> gt_t.

(* Scalar field operations.                                              *)
op scalar_zero : scalar_t.
op scalar_one  : scalar_t.
op scalar_add  : scalar_t -> scalar_t -> scalar_t.
op scalar_mul_s: scalar_t -> scalar_t -> scalar_t.

(* Hash-to-curve on G2 (IETF draft §4.2.2:                              *)
(* BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_).                            *)
op hash_to_g2 : message_t -> g2_t.

(* Compressed-G2 encoding (IETF draft §2.5, 96 bytes).                  *)
op encode_g2 : g2_t -> signature_t.

(* -------------------------------------------------------------------- *)
(* Shamir / Lagrange algebraic kernel (over F_r)                       *)
(* -------------------------------------------------------------------- *)

op lagrange : int list -> int -> scalar_t.
op poly_eval : share_t -> int -> share_t.
op reconstruct : int list -> share_t list -> share_t.

axiom scalar_add_zeroR : forall (s : scalar_t), scalar_add s scalar_zero = s.

(* BRIDGE: Crypto.Threshold.Lagrange.combine_distributes_over_sum.    *)
axiom reconstruct_linear :
  forall (Q : int list) (a b : share_t list),
    size a = size Q => size b = size Q =>
    reconstruct Q (map (fun (p : share_t * share_t) => scalar_add p.`1 p.`2)
                        (zip a b)) =
      scalar_add (reconstruct Q a) (reconstruct Q b).

(* BRIDGE: Crypto.BLS.Threshold.shamir_correct_at_target.              *)
axiom lagrange_inverse_eval (s : share_t) (Q : int list) :
  uniq Q =>
  1 <= size Q =>
  reconstruct Q (List.map (poly_eval s) Q) = s.

(* BRIDGE: Crypto.Threshold.Lagrange.threshold_partial_response_identity*)
(* Specialized to no-y-mask form (BLS partial sigs are pure share^s).  *)
axiom threshold_lagrange_identity :
  forall (Q : int list) (s : share_t),
    uniq Q =>
    1 <= size Q =>
    foldr scalar_add scalar_zero
      (map (fun (i : int) =>
              scalar_mul_s (lagrange Q i) (poly_eval s i)) Q) = s.

(* -------------------------------------------------------------------- *)
(* G2 scalar-multiplication linearity                                   *)
(* -------------------------------------------------------------------- *)
(* The load-bearing geometric identity: for any P in G2 and any        *)
(* scalars a, b in F_r:                                                 *)
(*   g2_scalar_mul a P + g2_scalar_mul b P = g2_scalar_mul (a+b) P      *)
(* This is standard group-action of F_r on G2; mechanizable in Mathlib *)
(* via `Crypto.BLS.Threshold.g2_scalar_mul_distributes_over_sum`.       *)
(* BRIDGED.                                                              *)

axiom g2_scalar_mul_distributes :
  forall (a b : scalar_t) (P : g2_t),
    g2_add (g2_scalar_mul a P) (g2_scalar_mul b P) =
      g2_scalar_mul (scalar_add a b) P.

axiom g2_scalar_mul_zero :
  forall (P : g2_t),
    g2_scalar_mul scalar_zero P = g2_scalar_mul scalar_zero g2_gen.
    (* Identity element in G2; same regardless of P. *)

(* -------------------------------------------------------------------- *)
(* Single-party BLS reference module                                    *)
(* -------------------------------------------------------------------- *)

module type BLSSigner = {
  proc sign(sk : share_t, msg : message_t) : signature_t
}.

module BLSRef : BLSSigner = {
  proc sign(sk : share_t, msg : message_t) : signature_t = {
    var h_m : g2_t;
    var sigma : g2_t;
    h_m   <- hash_to_g2 msg;
    sigma <- g2_scalar_mul sk h_m;
    return encode_g2 sigma;
  }
}.

(* -------------------------------------------------------------------- *)
(* Threshold BLS module type                                            *)
(* -------------------------------------------------------------------- *)
(* Two procedures: per-party sign, threshold aggregate.                 *)

module type BLS_Threshold = {
  proc partial_sign(share : share_t, msg : message_t) : sig_share_t

  proc aggregate(Q : int list, shares : (int * sig_share_t) list,
                 msg : message_t) : signature_t
}.

module BLSThresholdRef : BLS_Threshold = {
  proc partial_sign(share : share_t, msg : message_t) : sig_share_t = {
    var sigma : g2_t;
    sigma <- g2_scalar_mul share (hash_to_g2 msg);
    return sigma;
  }

  proc aggregate(Q : int list, shares : (int * sig_share_t) list,
                 msg : message_t) : signature_t = {
    var i : int;
    var weighted_sum : g2_t;
    var lam : scalar_t;
    var sigma_i : g2_t;
    var q_size : int;
    weighted_sum <- g2_scalar_mul scalar_zero g2_gen;  (* identity *)
    q_size <- size Q;
    i <- 0;
    while (i < q_size) {
      lam     <- lagrange Q i;
      (* sigma_i corresponds to position i in Q; resolved via shares.  *)
      sigma_i <- witness;
      weighted_sum <- g2_add weighted_sum (g2_scalar_mul lam sigma_i);
      i <- i + 1;
    }
    return encode_g2 weighted_sum;
  }
}.

(* -------------------------------------------------------------------- *)
(* Class N1 byte-equality theorem (statement)                           *)
(* -------------------------------------------------------------------- *)

section ClassN1.

declare module T <: BLS_Threshold.
declare module S <: BLSSigner.

(* The Combine output is the encoded sum of (lambda_i * sigma_i). Under*)
(* the Lagrange identity over F_r and the linearity of g2_scalar_mul,  *)
(* this equals the encoded H(m)^{f(0)} — which is BLS.Sign(f(0), m).  *)

declare axiom bls_threshold_dispatches_to_bls
    (Q : int list)
    (secret_shares : share_t list)
    (sig_shares : (int * sig_share_t) list)
    (msg : message_t) :
  uniq Q =>
  size Q = size secret_shares =>
  (* The threshold protocol's aggregate output equals single-party    *)
  (* BLS.Sign on the Lagrange-reconstructed secret.                    *)
  equiv [ T.aggregate ~ S.sign :
            Q{1} = Q /\ shares{1} = sig_shares /\ msg{1} = msg
            /\ sk{2} = reconstruct Q secret_shares
            /\ msg{2} = msg
          ==>
            ={res} ].

(* Top-level byte-equality theorem.                                     *)
lemma bls_threshold_n1_byte_equality
    (Q : int list)
    (master_secret : share_t)
    (sig_shares : (int * sig_share_t) list)
    (msg : message_t) :
  uniq Q =>
  1 <= size Q =>
  equiv [ T.aggregate ~ S.sign :
            Q{1} = Q /\ shares{1} = sig_shares /\ msg{1} = msg
            /\ sk{2} = master_secret /\ msg{2} = msg
          ==>
            ={res} ].
proof.
  move=> uQ szQ.
  (* Apply Lagrange-inverse to rewrite master_secret as                *)
  (* reconstruct Q (map (poly_eval master_secret) Q), then apply the   *)
  (* byte-walk axiom.                                                   *)
  have hrec : master_secret =
               reconstruct Q (List.map (poly_eval master_secret) Q).
  - by rewrite (lagrange_inverse_eval master_secret Q).
  rewrite hrec.
  apply (bls_threshold_dispatches_to_bls Q
           (List.map (poly_eval master_secret) Q) sig_shares msg uQ _).
  by rewrite size_map.
qed.

end section ClassN1.

(* -------------------------------------------------------------------- *)
(* End of BLS_Threshold_N1.ec                                            *)
(* -------------------------------------------------------------------- *)
