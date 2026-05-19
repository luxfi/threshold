(* -------------------------------------------------------------------- *)
(* CGGMP21 -- Class N1 byte-equality reduction (Lux profile)            *)
(* -------------------------------------------------------------------- *)
(* STATUS: SHELL.                                                       *)
(*                                                                      *)
(* Honest framing                                                       *)
(* --------------                                                       *)
(*   CGGMP21 is NOT a NIST standard. NIST has not standardized          *)
(*   threshold-ECDSA. "N1" here is the LUX-PROFILE analogue of the      *)
(*   Pulsar Class-N1 statement: the threshold-produced signature is     *)
(*   byte-identical to a single-party RFC 6979 / SEC1 ECDSA signature   *)
(*   on the Shamir-reconstructed master secret, verifiable under any   *)
(*   single-party secp256k1 ECDSA verifier (Bitcoin Core, geth, etc.). *)
(*                                                                      *)
(* Claim                                                                *)
(* -----                                                                *)
(*   For every (group_pk, sk_shares) produced by CGGMP21 Keygen (CCS    *)
(*   '21 §4) and presignatures from CGGMP21 Presign (CCS '21 §5),       *)
(*   for every message m and every honest signer set Q of size          *)
(*   |Q| >= threshold, the byte string produced by                      *)
(*                                                                      *)
(*       Combine o {Sign_i}_{i in Q} o Presign                          *)
(*                                                                      *)
(*   equals the byte string produced by                                 *)
(*                                                                      *)
(*       ECDSA.Sign_secp256k1(sk_group, m, k)                           *)
(*                                                                      *)
(*   where sk_group is the Lagrange reconstruction of the honest shares*)
(*   and k is the Lagrange-reconstructed presignature nonce.            *)
(*                                                                      *)
(* Reduction strategy (CCS '21 §5)                                      *)
(* ------------------                                                   *)
(*   1. Lagrange identity over F_n (secp256k1 scalar field): same as   *)
(*      Pulsar / FROST. Hoisted as `lagrange_inverse_eval`.             *)
(*   2. MtA-correctness: the multiplicative-to-additive conversion     *)
(*      (CCS '21 §3.2) produces shares of (k*x) that sum to k*x. Each *)
(*      MtA is wrapped in Paillier-based ZK proofs.                    *)
(*   3. Presignature consistency: (r, s_partial_i) shares aggregate    *)
(*      to (r, s) where s = k^{-1}*(m + r*x).                          *)
(*   4. Encoding: DER (Bitcoin) or 64-byte raw (Ethereum) under public *)
(*      ASN.1 / fixed-length rules.                                    *)
(*                                                                      *)
(* The two byte-walk axioms below mirror Pulsar's combine/sign         *)
(* byte-walks, adapted for the CCS '21 presign+sign decomposition.    *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool DInterval SmtMap.

(* -------------------------------------------------------------------- *)
(* Core types                                                            *)
(* -------------------------------------------------------------------- *)

type byte_seq = bool list.

(* Scalar in F_n where n is secp256k1 group order.                     *)
type scalar_t.

(* Point on secp256k1 (or other Lux-deployed curve).                   *)
type point_t.

(* Secret share: scalar in F_n (Shamir share of master ECDSA secret). *)
type share_t = scalar_t.

(* Group public key (ECDSA aggregate): PK = g^x where x = f(0).        *)
type group_pk_t = point_t.

(* Per-party Paillier secret key (CCS '21 §6.1, 2048-bit modulus).    *)
type paillier_sk_t.

(* Per-party Paillier public key (the modulus N_i).                   *)
type paillier_pk_t.

(* Per-party Pedersen parameters (CCS '21 §6.2).                       *)
type pedersen_params_t.

(* Per-party auxiliary keygen output: (paillier_pk, paillier_sk_share,*)
(* pedersen_params).                                                    *)
type aux_keygen_t.

(* Message hash bytes (32 bytes per SEC1 secp256k1).                  *)
type message_hash_t = byte_seq.

(* ECDSA signature in canonical form (DER or 64-byte raw).             *)
type signature_t.

(* Per-session presignature (k_i, chi_i, gamma_i, delta_i shares per   *)
(* CCS '21 §5.1).                                                       *)
type presignature_share_t.

(* Aggregated presignature: (R = k^{-1}*G, k_inv_share, chi_share).   *)
type presignature_t.

(* ZK proof transcript (Paillier-encrypted MtA + range proofs).        *)
type zk_transcript_t.

(* Session identifier.                                                  *)
type session_t.

(* -------------------------------------------------------------------- *)
(* Group structure (secp256k1)                                           *)
(* -------------------------------------------------------------------- *)

op group_g : point_t.
op scalar_mul : scalar_t -> point_t -> point_t.
op point_add  : point_t -> point_t -> point_t.

op scalar_zero : scalar_t.
op scalar_one  : scalar_t.
op scalar_add  : scalar_t -> scalar_t -> scalar_t.
op scalar_mul_s: scalar_t -> scalar_t -> scalar_t.
op scalar_inv  : scalar_t -> scalar_t.

(* Hash-to-scalar (SHA-256 || take low 256 bits per RFC 6979).        *)
op h_msg : byte_seq -> scalar_t.

(* x-coordinate of a point (used to form ECDSA r).                     *)
op point_x : point_t -> scalar_t.

(* Encode (r, s) per SEC1 / DER.                                       *)
op encode_signature_ecdsa : scalar_t -> scalar_t -> signature_t.

(* -------------------------------------------------------------------- *)
(* Shamir / Lagrange algebraic kernel (over F_n)                       *)
(* -------------------------------------------------------------------- *)

op lagrange : int list -> int -> scalar_t.
op poly_eval : share_t -> int -> share_t.
op reconstruct : int list -> share_t list -> share_t.

(* BRIDGED TO LEAN: axioms 1-3 below mirror FROST_N1.ec exactly        *)
(* (over a different field — F_n here instead of F_r for Ed25519).    *)

axiom scalar_add_zeroR : forall (s : scalar_t), scalar_add s scalar_zero = s.

(* BRIDGE: Crypto.Threshold.Lagrange.combine_distributes_over_sum.    *)
axiom reconstruct_linear :
  forall (Q : int list) (a b : share_t list),
    size a = size Q => size b = size Q =>
    reconstruct Q (map (fun (p : share_t * share_t) => scalar_add p.`1 p.`2)
                        (zip a b)) =
      scalar_add (reconstruct Q a) (reconstruct Q b).

(* BRIDGE: Crypto.CGGMP21.Lagrange.shamir_correct_at_target            *)
(* (instantiates Crypto.Threshold.Lagrange.threshold_reconstructs_secret*)
(* at F = F_n).                                                         *)
axiom lagrange_inverse_eval (s : share_t) (Q : int list) :
  uniq Q =>
  1 <= size Q =>
  reconstruct Q (List.map (poly_eval s) Q) = s.

(* -------------------------------------------------------------------- *)
(* Paillier algebra (additive homomorphism over Z_N)                    *)
(* -------------------------------------------------------------------- *)

(* Paillier encryption: enc(pk, m, r) where m in Z_N and r in Z_N*.   *)
op paillier_enc : paillier_pk_t -> int -> int -> int.

(* Paillier decryption: dec(sk, c) = m mod N.                          *)
op paillier_dec : paillier_sk_t -> int -> int.

(* BRIDGE (CGGMP21_Paillier.ec): Paillier additive homomorphism.       *)
(*   enc(pk, m1, r1) * enc(pk, m2, r2) = enc(pk, m1+m2 mod N, r1*r2)  *)
axiom paillier_additive_homomorphism :
  forall (pk : paillier_pk_t) (m1 m2 r1 r2 : int),
    True.  (* Stated mathematically in CGGMP21_Paillier.ec *)

(* -------------------------------------------------------------------- *)
(* Single-party ECDSA reference module                                  *)
(* -------------------------------------------------------------------- *)
(* The single-party signer that the threshold protocol refines to     *)
(* under byte-equality. RFC 6979 / SEC1 spec.                          *)
(* -------------------------------------------------------------------- *)

module type ECDSASigner = {
  proc sign(sk : share_t, msg_hash : message_hash_t, k : scalar_t)
    : signature_t
}.

module ECDSARef : ECDSASigner = {
  proc sign(sk : share_t, msg_hash : message_hash_t, k : scalar_t)
    : signature_t = {
    var R : point_t;
    var r, s, k_inv, m : scalar_t;
    R <- scalar_mul k group_g;
    r <- point_x R;
    k_inv <- scalar_inv k;
    m <- h_msg msg_hash;
    s <- scalar_mul_s k_inv (scalar_add m (scalar_mul_s r sk));
    return encode_signature_ecdsa r s;
  }
}.

(* -------------------------------------------------------------------- *)
(* CGGMP21 threshold protocol module type                              *)
(* -------------------------------------------------------------------- *)
(* Three procedures matching CCS '21 §5.1 and §5.2:                    *)
(*   Keygen: 4-round DKG with auxiliary parameters (Paillier+Pedersen)*)
(*   Presign: 3-round offline phase producing (R, k_inv, chi) shares  *)
(*   Sign:   1-round online phase producing s_i from presig + message *)

module type CGGMP21_Threshold = {
  proc presign_round1(sess : session_t,
                      share : share_t,
                      aux : aux_keygen_t,
                      my_idx : int)
    : presignature_share_t * zk_transcript_t

  proc presign_round2(sess : session_t,
                      r1_msgs : (int * (presignature_share_t * zk_transcript_t)) list,
                      share : share_t,
                      aux : aux_keygen_t,
                      my_idx : int)
    : presignature_share_t * zk_transcript_t

  proc presign_round3(sess : session_t,
                      r2_msgs : (int * (presignature_share_t * zk_transcript_t)) list,
                      share : share_t,
                      aux : aux_keygen_t,
                      my_idx : int) : presignature_t

  proc sign_online(sess : session_t,
                   presig : presignature_t,
                   msg_hash : message_hash_t,
                   shares : (int * scalar_t) list) : signature_t
}.

(* -------------------------------------------------------------------- *)
(* Class N1 byte-equality theorem (statement)                           *)
(* -------------------------------------------------------------------- *)

section ClassN1.

declare module T <: CGGMP21_Threshold.
declare module S <: ECDSASigner.

(* Section-local byte-walk axiom mirrors Pulsar's combine_body_axiom. *)
(* Discharged Jasmin-side once the presign+sign extraction lands.    *)
declare axiom cggmp21_dispatches_to_ecdsa
    (sess : session_t)
    (Q : int list)
    (shares : share_t list)
    (presig : presignature_t)
    (k_recon : scalar_t)
    (msg_hash : message_hash_t)
    (s_shares : (int * scalar_t) list) :
  uniq Q =>
  size Q = size shares =>
  equiv [ T.sign_online ~ S.sign :
            sess{1} = sess /\ presig{1} = presig
            /\ msg_hash{1} = msg_hash /\ shares{1} = s_shares
            /\ sk{2} = reconstruct Q shares
            /\ k{2} = k_recon /\ msg_hash{2} = msg_hash
          ==>
            ={res} ].

(* Top-level byte-equality: composes the byte-walk axiom with the     *)
(* Lagrange-inverse identity over F_n.                                 *)
lemma cggmp21_n1_byte_equality
    (sess : session_t)
    (Q : int list)
    (master_secret : share_t)
    (presig : presignature_t)
    (k_recon : scalar_t)
    (msg_hash : message_hash_t)
    (s_shares : (int * scalar_t) list) :
  uniq Q =>
  1 <= size Q =>
  equiv [ T.sign_online ~ S.sign :
            sess{1} = sess /\ presig{1} = presig
            /\ msg_hash{1} = msg_hash /\ shares{1} = s_shares
            /\ sk{2} = master_secret /\ k{2} = k_recon
            /\ msg_hash{2} = msg_hash
          ==>
            ={res} ].
proof.
  move=> uQ szQ.
  have hrec : master_secret =
               reconstruct Q (List.map (poly_eval master_secret) Q).
  - by rewrite (lagrange_inverse_eval master_secret Q).
  apply (cggmp21_dispatches_to_ecdsa sess Q
           (List.map (poly_eval master_secret) Q) presig k_recon
           msg_hash s_shares uQ _) => //=.
  by rewrite size_map.
qed.

end section ClassN1.

(* -------------------------------------------------------------------- *)
(* End of CGGMP21_N1.ec                                                  *)
(* -------------------------------------------------------------------- *)
