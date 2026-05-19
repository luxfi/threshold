(* -------------------------------------------------------------------- *)
(* CGGMP21 -- Class N1 keygen / presign / sign refinement               *)
(* -------------------------------------------------------------------- *)
(* STATUS: SHELL.                                                       *)
(*                                                                      *)
(* This file states the round-by-round refinement obligations between   *)
(* the abstract CGGMP21_Threshold module type and a concrete extraction *)
(* (the Go reference at `~/work/lux/threshold/protocols/cmp/`).         *)
(* The full mechanization is gated on the Jasmin extraction of the      *)
(* threshold layer, which is itself gated on a libjade port of Paillier *)
(* (no such port exists today — the CCS '21 §6.1 prime-quality checks   *)
(* are nontrivial in Jasmin).                                            *)
(* -------------------------------------------------------------------- *)
(* Concern boundary                                                      *)
(* ----------------                                                      *)
(*   This file owns the procedure-level equivalences:                    *)
(*     - Keygen refinement: 4-round DKG producing                       *)
(*         (group_pk, shares, paillier_aux, pedersen_aux).              *)
(*     - Presign refinement: 3-round MtA + ZK proof exchange producing  *)
(*         (R, k_inv_share, chi_share).                                 *)
(*     - Sign refinement: 1-round online phase producing s_i.            *)
(*                                                                      *)
(*   Each refinement is stated as an `equiv` between the abstract       *)
(*   module-type interface and a concrete module that mirrors the       *)
(*   reference Go code in `protocols/cmp/{keygen,presign,sign}/`.      *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool DInterval SmtMap.
require import CGGMP21_N1.

(* Concrete reference module (mirrors protocols/cmp/{keygen,presign,sign}/*.go). *)
module CGGMP21_Ref : CGGMP21_Threshold = {
  proc presign_round1(sess : session_t,
                      share : share_t,
                      aux : aux_keygen_t,
                      my_idx : int)
    : presignature_share_t * zk_transcript_t = {
    var pshare : presignature_share_t;
    var zk : zk_transcript_t;
    pshare <- witness;
    zk <- witness;
    return (pshare, zk);
  }

  proc presign_round2(sess : session_t,
                      r1_msgs : (int * (presignature_share_t * zk_transcript_t)) list,
                      share : share_t,
                      aux : aux_keygen_t,
                      my_idx : int)
    : presignature_share_t * zk_transcript_t = {
    var pshare : presignature_share_t;
    var zk : zk_transcript_t;
    pshare <- witness;
    zk <- witness;
    return (pshare, zk);
  }

  proc presign_round3(sess : session_t,
                      r2_msgs : (int * (presignature_share_t * zk_transcript_t)) list,
                      share : share_t,
                      aux : aux_keygen_t,
                      my_idx : int) : presignature_t = {
    var p : presignature_t;
    p <- witness;
    return p;
  }

  proc sign_online(sess : session_t,
                   presig : presignature_t,
                   msg_hash : message_hash_t,
                   shares : (int * scalar_t) list) : signature_t = {
    var sig : signature_t;
    sig <- witness;
    return sig;
  }
}.

(* -------------------------------------------------------------------- *)
(* Presign Round 1 refinement obligation                                 *)
(* -------------------------------------------------------------------- *)
(* Each party samples (k_i, gamma_i) uniformly from F_n*, commits to    *)
(* Paillier-encrypted k_i + Pedersen-randomized gamma_i with a ZK proof.*)
(* See CCS '21 §5.1 Round 1.                                            *)

op uniform_nonzero_scalar : scalar_t distr.

module CGGMP21_Presign_R1_Spec = {
  proc presign_round1(sess : session_t,
                      share : share_t,
                      aux : aux_keygen_t,
                      my_idx : int)
    : presignature_share_t * zk_transcript_t = {
    var k_i, gamma_i : scalar_t;
    var pshare : presignature_share_t;
    var zk : zk_transcript_t;
    k_i     <$ uniform_nonzero_scalar;
    gamma_i <$ uniform_nonzero_scalar;
    pshare  <- witness;  (* (paillier_enc(N_i, k_i, r_k_i),                 *)
                         (*  paillier_enc(N_i, gamma_i, r_g_i),             *)
                         (*  pedersen_commit(gamma_i, r_g'_i))             *)
    zk      <- witness;  (* {ZK_log_paillier, ZK_log_pedersen, ZK_eq...} *)
    return (pshare, zk);
  }
}.

axiom presign_round1_refinement_axiom :
    equiv [ CGGMP21_Ref.presign_round1 ~ CGGMP21_Presign_R1_Spec.presign_round1 :
              ={sess, share, aux, my_idx}
            ==>
              ={res} ].

(* -------------------------------------------------------------------- *)
(* Presign Round 2 refinement obligation                                 *)
(* -------------------------------------------------------------------- *)
(* MtA: for each pair (i,j), parties exchange Paillier-MtA messages to *)
(* convert multiplicative shares (k_i, gamma_j) into additive shares    *)
(* alpha_{i,j} + beta_{i,j} = k_i * gamma_j. See CCS '21 §3.2.          *)

module CGGMP21_Presign_R2_Spec = {
  proc presign_round2(sess : session_t,
                      r1_msgs : (int * (presignature_share_t * zk_transcript_t)) list,
                      share : share_t,
                      aux : aux_keygen_t,
                      my_idx : int)
    : presignature_share_t * zk_transcript_t = {
    var pshare : presignature_share_t;
    var zk : zk_transcript_t;
    pshare <- witness;  (* {alpha_{j,i}: Paillier-add-resp from peer j} *)
    zk <- witness;
    return (pshare, zk);
  }
}.

axiom presign_round2_refinement_axiom :
    equiv [ CGGMP21_Ref.presign_round2 ~ CGGMP21_Presign_R2_Spec.presign_round2 :
              ={sess, r1_msgs, share, aux, my_idx}
            ==>
              ={res} ].

(* -------------------------------------------------------------------- *)
(* Presign Round 3 refinement obligation                                 *)
(* -------------------------------------------------------------------- *)
(* Compute Gamma = sum_j Gamma_j = (sum gamma_j)*G; R = Gamma^{k^{-1}}.*)
(* Each party knows their share of k_inv * x = chi_i.                  *)

module CGGMP21_Presign_R3_Spec = {
  proc presign_round3(sess : session_t,
                      r2_msgs : (int * (presignature_share_t * zk_transcript_t)) list,
                      share : share_t,
                      aux : aux_keygen_t,
                      my_idx : int) : presignature_t = {
    var p : presignature_t;
    p <- witness;
    return p;
  }
}.

axiom presign_round3_refinement_axiom :
    equiv [ CGGMP21_Ref.presign_round3 ~ CGGMP21_Presign_R3_Spec.presign_round3 :
              ={sess, r2_msgs, share, aux, my_idx}
            ==>
              ={res} ].

(* -------------------------------------------------------------------- *)
(* Sign refinement obligation                                            *)
(* -------------------------------------------------------------------- *)
(* Online phase: s_i = k_i_inv * m + r * chi_i (mod n).                *)
(* Sum across signers: s = sum s_i = k^{-1} * m + r * x (mod n).       *)

module CGGMP21_Sign_Spec = {
  proc sign_online(sess : session_t,
                   presig : presignature_t,
                   msg_hash : message_hash_t,
                   shares : (int * scalar_t) list) : signature_t = {
    var sig : signature_t;
    sig <- witness;
    return sig;
  }
}.

axiom sign_online_refinement_axiom :
    equiv [ CGGMP21_Ref.sign_online ~ CGGMP21_Sign_Spec.sign_online :
              ={sess, presig, msg_hash, shares}
            ==>
              ={res} ].

(* -------------------------------------------------------------------- *)
(* End of CGGMP21_N1_Refinement.ec                                       *)
(* -------------------------------------------------------------------- *)
