(* -------------------------------------------------------------------- *)
(* FROST -- Class N1 byte-equality reduction (Lux profile)              *)
(* -------------------------------------------------------------------- *)
(* STATUS: SHELL.                                                       *)
(*                                                                      *)
(* Honest framing                                                       *)
(* --------------                                                       *)
(*   FROST is NOT a NIST standard. There is no FIPS verifier to be      *)
(*   byte-equal to. "N1" here is the LUX-PROFILE analogue of the Pulsar *)
(*   Class-N1 statement: the threshold-produced signature is byte-      *)
(*   identical to a single-party Schnorr signature on the Shamir-       *)
(*   reconstructed master secret, verifiable under the canonical        *)
(*   single-party verifier for the pinned ciphersuite (Ed25519 RFC 8032 *)
(*   or secp256k1 BIP-340 Taproot). The Lux-profile "single-party       *)
(*   verifier" is therefore EITHER `crypto/ed25519` (Ed25519) OR        *)
(*   `crypto/secp256k1` Schnorr/BIP-340 (Taproot), depending on the     *)
(*   pinned ciphersuite. See `FROST_Ciphersuite_*.ec` for the           *)
(*   ciphersuite-layer hand-off.                                        *)
(*                                                                      *)
(* Claim                                                                *)
(* -----                                                                *)
(*   For every (group_pk, sk_shares) produced by FROST Keygen (Komlo-   *)
(*   Goldberg Fig. 1), for every message m and every honest signer set  *)
(*   Q of size |Q| >= threshold, the byte string produced by            *)
(*                                                                      *)
(*       Combine o {Sign_R2_i}_{i in Q} o {Sign_R1_i}_{i in Q}          *)
(*                                                                      *)
(*   equals the byte string produced by                                 *)
(*                                                                      *)
(*       Schnorr.Sign(sk_group, m)                                      *)
(*                                                                      *)
(*   where sk_group is the Lagrange reconstruction (at X = 0) of the    *)
(*   honest-quorum shares under the same per-session nonce derivation.  *)
(*                                                                      *)
(* Reduction strategy (Komlo-Goldberg SAC 2020 / ePrint 2020/852 §4)    *)
(* -----------------------------------------------------------------    *)
(*   1. Lagrange-at-zero identity for the secret share polynomial.     *)
(*      Hoisted as `lagrange_inverse_eval` axiom; bridged to            *)
(*      `Crypto.FROST.Lagrange.shamir_correct_at_target` in Lean.      *)
(*   2. Per-party nonce commitment aggregation: R = sum_i R_i is the    *)
(*      Schnorr commitment of the aggregated nonce r = sum_i d_i + e_i  *)
(*      times the binding factor.                                       *)
(*   3. Per-party response aggregation: z = sum_i z_i = sum_i           *)
(*      (d_i + rho_i*e_i + c * lambda_i * s_i) = r + c*s under the      *)
(*      Lagrange identity above.                                        *)
(*   4. Group public key reconstruction: PK = g^s is invariant under    *)
(*      Lagrange (commits to the polynomial's constant term).           *)
(*                                                                      *)
(* Honest framing: this file states the obligation surface as module    *)
(* types and the top-level `frost_n1_byte_equality` theorem. The full   *)
(* mechanization is multi-month research (see                           *)
(* `~/work/lux/threshold/protocols/frost/SUBMISSION-STATUS.md §3.5`).   *)
(* The two byte-walk axioms over the Combine output (analogous to       *)
(* Pulsar's combine/sign byte-walks) remain `admit`-tagged below;       *)
(* every admit is enumerated in `AXIOM-INVENTORY.md`.                   *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool DInterval SmtMap.

(* -------------------------------------------------------------------- *)
(* Core types -- byte universe + FROST nominal types                    *)
(* -------------------------------------------------------------------- *)

type byte_seq = bool list.

(* Scalar in F_r where r is the group order of the pinned ciphersuite.  *)
(* Abstract: the concrete field is filled in by the ciphersuite layer   *)
(* (Ed25519's edwards25519 scalar field or secp256k1's scalar field).   *)
type scalar_t.

(* Group element (curve point) in the pinned ciphersuite's prime-order  *)
(* subgroup. Abstract for the same reason.                               *)
type point_t.

(* Secret share: scalar in F_r (Shamir share of the master Schnorr      *)
(* secret).                                                              *)
type share_t = scalar_t.

(* Per-party verification share: PK_i = g^{s_i} on the curve. Public.  *)
type vshare_t = point_t.

(* Group public key (Schnorr aggregate): PK = g^s where s = f(0).      *)
type group_pk_t = point_t.

(* Message bytes.                                                        *)
type message_t = byte_seq.

(* Single-party Schnorr signature byte encoding (ciphersuite-dependent: *)
(* 64 bytes for both Ed25519 RFC 8032 and secp256k1 BIP-340).            *)
type signature_t.

(* Per-session per-party nonces: (d_i, e_i) pair of fresh scalars.     *)
type nonce_pair_t = scalar_t * scalar_t.

(* Per-party Round-1 commitment: (D_i = g^{d_i}, E_i = g^{e_i}).        *)
type commit_pair_t = point_t * point_t.

(* Round-1 aggregated commitment list across the signing quorum.       *)
type commit_list_t = (int * commit_pair_t) list.

(* Round-2 signature share: z_i in F_r.                                *)
type share_response_t = scalar_t.

(* Per-session state binding (transcript, message, quorum identifiers).*)
type session_t.

(* Per-session ciphersuite identifier. Pinned values:                   *)
(*   - "FROST(Ed25519, SHA-512)"            (Lux LP-4711)               *)
(*   - "FROST(secp256k1, SHA-256) + Taproot"  (Lux LP-4712)             *)
type ciphersuite_id_t.

(* -------------------------------------------------------------------- *)
(* Group structure                                                       *)
(* -------------------------------------------------------------------- *)

(* Group generator (g in Ed25519 / B in secp256k1).                     *)
op group_g : point_t.

(* Scalar multiplication: scalar acting on a point.                     *)
op scalar_mul : scalar_t -> point_t -> point_t.

(* Point addition (group operation).                                    *)
op point_add : point_t -> point_t -> point_t.

(* Scalar field operations.                                             *)
op scalar_zero : scalar_t.
op scalar_one  : scalar_t.
op scalar_add  : scalar_t -> scalar_t -> scalar_t.
op scalar_mul_s: scalar_t -> scalar_t -> scalar_t.
op scalar_neg  : scalar_t -> scalar_t.

(* Inverse in F_r (defined for nonzero scalars; undefined otherwise).  *)
op scalar_inv  : scalar_t -> scalar_t.

(* Random oracle: H1 (binding factor), H2 (challenge), H3 (nonce        *)
(* derivation). Modelled as abstract operations; the ciphersuite layer  *)
(* pins concrete SHA-512 / SHA-256 instantiations.                      *)
op h_binding : byte_seq -> scalar_t.
op h_challenge : byte_seq -> scalar_t.
op h_nonce : byte_seq -> scalar_t.

(* -------------------------------------------------------------------- *)
(* Shamir / Lagrange algebraic kernel                                   *)
(* -------------------------------------------------------------------- *)
(* These operators name the Shamir layer over F_r. The Lean theory      *)
(* `Crypto.FROST.Lagrange` mechanizes their algebraic content; here we  *)
(* hoist the facts the byte-equality proof depends on.                  *)
(* -------------------------------------------------------------------- *)

(* Lagrange coefficient at X = 0 for party index `i` in quorum `Q`.    *)
(* Returns lambda_i = prod_{j in Q, j != i} (0 - x_j) / (x_i - x_j)    *)
(* in F_r.                                                              *)
op lagrange : int list -> int -> scalar_t.

(* Polynomial evaluation: given a share-representative polynomial      *)
(* (constant term = secret), evaluate at index i to get share_i.       *)
op poly_eval : share_t -> int -> share_t.

(* Reconstruction: take a quorum and a list of shares, return the      *)
(* Shamir-reconstructed secret at X = 0.                                *)
op reconstruct : int list -> share_t list -> share_t.

(* BRIDGED TO LEAN: the four axioms below correspond 1:1 to proved      *)
(* Lean theorems in `~/work/lux/proofs/lean/Crypto/`. Inline citations  *)
(* given per-axiom; the full symbol-correspondence table lives in       *)
(* `~/work/lux/threshold/protocols/frost/proofs/lean-easycrypt-         *)
(* bridge.md`.                                                          *)

(* Adding zero is identity in F_r.                                      *)
(* BRIDGE: instance fact for any AddCommMonoid (Mathlib auto-derives    *)
(* for any Field F). See bridge doc Axiom 1.                            *)
axiom scalar_add_zeroR : forall (s : scalar_t), scalar_add s scalar_zero = s.

(* BRIDGE: Crypto.FROST.Lagrange.combine_distributes_over_sum           *)
(* (`~/work/lux/proofs/lean/Crypto/Threshold_Lagrange.lean:81`).        *)
(* Reconstruction is linear over share-list addition.                   *)
axiom reconstruct_linear :
  forall (Q : int list) (a b : share_t list),
    size a = size Q => size b = size Q =>
    reconstruct Q (map (fun (p : share_t * share_t) => scalar_add p.`1 p.`2)
                        (zip a b)) =
      scalar_add (reconstruct Q a) (reconstruct Q b).

(* BRIDGE: Crypto.FROST.Lagrange.shamir_correct_at_target              *)
(* (Lagrange-at-zero inversion). Reconstruction inverts poly_eval over *)
(* any quorum of size >= degree+1.                                      *)
axiom lagrange_inverse_eval (s : share_t) (Q : int list) :
  uniq Q =>
  1 <= size Q =>
  reconstruct Q (List.map (poly_eval s) Q) = s.

(* BRIDGE: Crypto.FROST.Lagrange.threshold_partial_response_identity   *)
(* (`~/work/lux/proofs/lean/Crypto/Threshold_Lagrange.lean:135`).      *)
(* Sum of (lambda_i * share_i) over a quorum equals the secret.        *)
axiom threshold_partial_response_identity :
  forall (Q : int list) (s : share_t),
    uniq Q =>
    1 <= size Q =>
    foldr scalar_add scalar_zero
      (map (fun (i : int) =>
              scalar_mul_s (lagrange Q i) (poly_eval s i)) Q) = s.

(* -------------------------------------------------------------------- *)
(* FROST single-party Schnorr abstract spec                              *)
(* -------------------------------------------------------------------- *)
(* This module type captures the single-party Schnorr signer that the   *)
(* threshold protocol refines to under byte-equality. The pinned        *)
(* ciphersuite layer (`FROST_Ciphersuite_Ed25519.ec` /                  *)
(* `FROST_Ciphersuite_Secp256k1_Taproot.ec`) instantiates the bytes     *)
(* concretely; this file stays ciphersuite-agnostic.                    *)
(* -------------------------------------------------------------------- *)

module type SchnorrSigner = {
  proc sign(sk : share_t, msg : message_t) : signature_t
}.

module type SchnorrVerifier = {
  proc verify(pk : group_pk_t, msg : message_t, sig : signature_t) : bool
}.

(* Abstract single-party Schnorr Sign — the ciphersuite layer fills in *)
(* the encoding step (Ed25519 RFC 8032 §5.1.6 / BIP-340 §6.6 sign).    *)
module SchnorrSign : SchnorrSigner = {
  proc sign(sk : share_t, msg : message_t) : signature_t = {
    var sig : signature_t;
    sig <- witness;  (* Concrete value pinned by ciphersuite layer. *)
    return sig;
  }
}.

(* -------------------------------------------------------------------- *)
(* FROST threshold module type (3-round: KG, R1, R2)                   *)
(* -------------------------------------------------------------------- *)

(* For the Sign protocol (Keygen lives in FROST_N4): three procedures   *)
(* matching Komlo-Goldberg Fig. 3 (Sign):                                *)
(*   Round 1: each party samples (d_i, e_i), publishes (D_i, E_i).      *)
(*   Round 2: each party computes z_i = d_i + rho_i*e_i + c*lambda_i*s_i*)
(*            where rho_i is the binding factor and c is the challenge. *)
(*   Combine: sum z_i, encode (R, z) per ciphersuite.                   *)

module type FROST_Threshold = {
  proc round1(sess : session_t, share : share_t, my_idx : int)
    : commit_pair_t * nonce_pair_t

  proc round2(sess : session_t, share : share_t, my_idx : int,
              nonces : nonce_pair_t, commits : commit_list_t,
              msg : message_t) : share_response_t

  proc combine(sess : session_t, commits : commit_list_t,
               shares : (int * share_response_t) list,
               group_pk : group_pk_t, msg : message_t) : signature_t
}.

(* -------------------------------------------------------------------- *)
(* Class N1 byte-equality theorem (statement)                           *)
(* -------------------------------------------------------------------- *)

section ClassN1.

declare module T <: FROST_Threshold.
declare module S <: SchnorrSigner.

(* Section-local hypothesis: T's Round-1 + Round-2 + Combine, run        *)
(* honestly across a quorum Q of size >= threshold, produces the same   *)
(* output bytes as S.sign(sk_group, msg) where sk_group is the           *)
(* reconstructed secret.                                                 *)
(*                                                                      *)
(* This is the byte-walk axiom — discharged Jasmin-side when a concrete *)
(* extraction is plugged in, exactly as Pulsar's combine/sign byte-walks*)
(* are discharged. See the roadmap in                                   *)
(* `~/work/lux/threshold/protocols/frost/proofs/easycrypt/AXIOM-        *)
(* INVENTORY.md`.                                                       *)

declare axiom frost_combine_dispatches_to_schnorr
    (sess : session_t)
    (Q : int list)
    (shares : share_t list)
    (commits : commit_list_t)
    (responses : (int * share_response_t) list)
    (group_pk : group_pk_t)
    (msg : message_t) :
  uniq Q =>
  size Q = size shares =>
  (* The threshold protocol's combine output equals single-party        *)
  (* Schnorr Sign on the Lagrange-reconstructed secret.                 *)
  equiv [ T.combine ~ S.sign :
            sess{1} = sess /\ commits{1} = commits
            /\ shares{1} = responses /\ group_pk{1} = group_pk
            /\ msg{1} = msg
            /\ sk{2} = reconstruct Q shares
            /\ msg{2} = msg
          ==>
            ={res} ].

(* Top-level byte-equality theorem. Composes the axiom above with the   *)
(* Lagrange-inverse identity to yield: the threshold output equals      *)
(* Schnorr Sign on the master secret f(0).                              *)
lemma frost_n1_byte_equality
    (sess : session_t)
    (Q : int list)
    (master_secret : share_t)
    (commits : commit_list_t)
    (responses : (int * share_response_t) list)
    (group_pk : group_pk_t)
    (msg : message_t) :
  uniq Q =>
  1 <= size Q =>
  (* The threshold output is byte-equal to the single-party output     *)
  (* on the master secret f(0).                                         *)
  equiv [ T.combine ~ S.sign :
            sess{1} = sess /\ commits{1} = commits
            /\ shares{1} = responses /\ group_pk{1} = group_pk
            /\ msg{1} = msg
            /\ sk{2} = master_secret
            /\ msg{2} = msg
          ==>
            ={res} ].
proof.
  move=> uQ szQ.
  (* Use the Lagrange-inverse identity to rewrite master_secret as     *)
  (* reconstruct Q (map (poly_eval master_secret) Q) (Axiom 3), then   *)
  (* apply the byte-walk axiom (frost_combine_dispatches_to_schnorr). *)
  (* Composition is direct: the proof is a single rewrite + apply.    *)
  have hrec : master_secret =
               reconstruct Q (List.map (poly_eval master_secret) Q).
  - by rewrite (lagrange_inverse_eval master_secret Q).
  apply (frost_combine_dispatches_to_schnorr sess Q
           (List.map (poly_eval master_secret) Q) commits responses
           group_pk msg uQ _) => //=.
  by rewrite size_map.
qed.

end section ClassN1.

(* -------------------------------------------------------------------- *)
(* End of FROST_N1.ec                                                    *)
(* -------------------------------------------------------------------- *)
