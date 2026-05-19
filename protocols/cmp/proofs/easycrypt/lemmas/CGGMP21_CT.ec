(* -------------------------------------------------------------------- *)
(* CGGMP21 -- Constant-time obligations on threshold-layer routines     *)
(* -------------------------------------------------------------------- *)
(* STATUS: SHELL. Same BGL leakage model as Pulsar and FROST.           *)
(* -------------------------------------------------------------------- *)
(* CGGMP21 secret-touching routines (mirror                              *)
(* `jasmin/{presign,threshold}/*.jazz`):                                 *)
(*   - presign_round1: secret = (k_i, gamma_i, paillier_sk)              *)
(*       Nonces sampled fresh per presign session.                       *)
(*   - presign_round2: secret = (k_i, gamma_i, paillier_sk,             *)
(*                                MtA-beta_j values)                     *)
(*       Paillier decryption of MtA responses is the CT-critical op.   *)
(*   - presign_round3: secret = (k_i, k_inv_share, chi_share)            *)
(*       Combine of all shares; control flow must be uniform.            *)
(*   - sign_online:    secret = (k_i_inv_share, chi_share, share)        *)
(*       Final s_i = k_i_inv * m + r * chi_i computation.                *)
(* -------------------------------------------------------------------- *)
(* The Paillier decryption CT story is delicate: CT decryption requires *)
(* careful modular exponentiation (CRT-based, with constant-time        *)
(* modular inverse). The Lux profile inherits CT from `pkg/paillier`    *)
(* which uses `cronokirby/saferith`. Stated as a refinement obligation. *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool.

type leakage_t.

type share_t.
type scalar_t.
type session_t.
type aux_keygen_t.
type presignature_share_t.
type zk_transcript_t.
type presignature_t.
type signature_t.
type message_hash_t.

module type CTPresignR1 = {
  proc presign_round1(sess : session_t, share : share_t,
                      aux : aux_keygen_t, my_idx : int)
    : presignature_share_t * zk_transcript_t * leakage_t
}.

module type CTPresignR2 = {
  proc presign_round2(sess : session_t,
                      r1_msgs : (int * (presignature_share_t * zk_transcript_t)) list,
                      share : share_t, aux : aux_keygen_t, my_idx : int)
    : presignature_share_t * zk_transcript_t * leakage_t
}.

module type CTPresignR3 = {
  proc presign_round3(sess : session_t,
                      r2_msgs : (int * (presignature_share_t * zk_transcript_t)) list,
                      share : share_t, aux : aux_keygen_t, my_idx : int)
    : presignature_t * leakage_t
}.

module type CTSign = {
  proc sign_online(sess : session_t, presig : presignature_t,
                   msg_hash : message_hash_t,
                   shares : (int * scalar_t) list)
    : signature_t * leakage_t
}.

(* -------------------------------------------------------------------- *)
(* Presign Round 1 CT obligation                                         *)
(* -------------------------------------------------------------------- *)

section PresignR1CT.

declare module P1 <: CTPresignR1.

declare axiom presign_round1_constant_time
      (sess : session_t)
      (share1 share2 : share_t)
      (aux1 aux2 : aux_keygen_t)
      (my_idx : int) :
    equiv [ P1.presign_round1 ~ P1.presign_round1 :
              ={sess, my_idx}
              /\ share{1} = share1 /\ share{2} = share2
              /\ aux{1} = aux1 /\ aux{2} = aux2
            ==>
              res{1}.`3 = res{2}.`3 ].

end section PresignR1CT.

(* -------------------------------------------------------------------- *)
(* Presign Round 2 CT obligation (Paillier MtA decryption)              *)
(* -------------------------------------------------------------------- *)

section PresignR2CT.

declare module P2 <: CTPresignR2.

declare axiom presign_round2_constant_time
      (sess : session_t)
      (share1 share2 : share_t)
      (aux1 aux2 : aux_keygen_t)
      (r1_msgs : (int * (presignature_share_t * zk_transcript_t)) list)
      (my_idx : int) :
    equiv [ P2.presign_round2 ~ P2.presign_round2 :
              ={sess, r1_msgs, my_idx}
              /\ share{1} = share1 /\ share{2} = share2
              /\ aux{1} = aux1 /\ aux{2} = aux2
            ==>
              res{1}.`3 = res{2}.`3 ].

end section PresignR2CT.

(* -------------------------------------------------------------------- *)
(* Presign Round 3 CT obligation                                         *)
(* -------------------------------------------------------------------- *)

section PresignR3CT.

declare module P3 <: CTPresignR3.

declare axiom presign_round3_constant_time
      (sess : session_t)
      (share1 share2 : share_t)
      (aux1 aux2 : aux_keygen_t)
      (r2_msgs : (int * (presignature_share_t * zk_transcript_t)) list)
      (my_idx : int) :
    equiv [ P3.presign_round3 ~ P3.presign_round3 :
              ={sess, r2_msgs, my_idx}
              /\ share{1} = share1 /\ share{2} = share2
              /\ aux{1} = aux1 /\ aux{2} = aux2
            ==>
              res{1}.`2 = res{2}.`2 ].

end section PresignR3CT.

(* -------------------------------------------------------------------- *)
(* Sign online CT obligation                                             *)
(* -------------------------------------------------------------------- *)

section SignCT.

declare module SO <: CTSign.

declare axiom sign_online_constant_time
      (presig : presignature_t)
      (msg_hash : message_hash_t)
      (sess : session_t)
      (s1 s2 : (int * scalar_t) list) :
    equiv [ SO.sign_online ~ SO.sign_online :
              ={sess, presig, msg_hash}
              /\ shares{1} = s1 /\ shares{2} = s2
            ==>
              res{1}.`2 = res{2}.`2 ].

end section SignCT.

(* -------------------------------------------------------------------- *)
(* End of CGGMP21_CT.ec                                                  *)
(* -------------------------------------------------------------------- *)
