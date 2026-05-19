(* -------------------------------------------------------------------- *)
(* FROST -- Constant-time obligations on threshold-layer routines       *)
(* -------------------------------------------------------------------- *)
(* STATUS: SHELL. The CT obligations are stated as section-local        *)
(* `declare axiom`s over the abstract modules R1, R2, R3 — leakage      *)
(* equivalence is concrete-impl-dependent. Refinement obligation is     *)
(* discharged Jasmin-side via `jasminc -checkCT` when a concrete        *)
(* extraction is plugged in, or empirically via dudect (when available).*)
(* -------------------------------------------------------------------- *)
(* Threat model:                                                         *)
(*   Barthe-Grégoire-Laporte leakage model (CSF 2018), matching the     *)
(*   Pulsar/libjade reference. The adversary observes control-flow      *)
(*   trace and memory-access pattern but not values at those addresses. *)
(*                                                                      *)
(* FROST secret-touching routines (mirror                                *)
(* `jasmin/threshold/{round1,round2,combine}.jazz`):                    *)
(*   - round1_commit:  secret = (d_i, e_i)                              *)
(*       Nonces (d_i, e_i) are secret; their group commitments         *)
(*       (D_i, E_i) are public. The CT property: scalar_mul g d_i must *)
(*       not leak d_i through control flow or memory pattern.           *)
(*   - round2_response: secret = (share s_i, nonces (d_i, e_i))          *)
(*       The response z_i = d_i + rho_i*e_i + c*lambda_i*s_i must be   *)
(*       computed without secret-dependent branches. rho_i, c, lambda_i*)
(*       are public.                                                    *)
(*   - combine:        no secret inputs => trivially CT.                *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool.

type leakage_t.

type share_t.
type scalar_t.
type point_t.
type session_t.
type commit_pair_t.
type commit_list_t.
type nonce_pair_t.
type share_response_t.
type message_t.

module type CTRound1 = {
  proc round1(sess : session_t, share : share_t, my_idx : int)
    : commit_pair_t * nonce_pair_t * leakage_t
}.

module type CTRound2 = {
  proc round2(sess : session_t, share : share_t, my_idx : int,
              nonces : nonce_pair_t, commits : commit_list_t,
              msg : message_t) : share_response_t * leakage_t
}.

(* -------------------------------------------------------------------- *)
(* Round-1 CT obligation                                                 *)
(* -------------------------------------------------------------------- *)

section Round1CT.

declare module R1 <: CTRound1.

(* The Round-1 trace must be independent of the secret nonces           *)
(* sampled internally. We model this by requiring that two              *)
(* executions with the same public inputs produce the same leakage      *)
(* trace, regardless of which scalars R1 samples internally.            *)

declare axiom round1_constant_time
      (sess : session_t)
      (share1 share2 : share_t)
      (my_idx : int) :
    equiv [ R1.round1 ~ R1.round1 :
              ={sess, my_idx}
              /\ share{1} = share1 /\ share{2} = share2
            ==>
              res{1}.`3 = res{2}.`3 ].

end section Round1CT.

(* -------------------------------------------------------------------- *)
(* Round-2 CT obligation                                                 *)
(* -------------------------------------------------------------------- *)

section Round2CT.

declare module R2 <: CTRound2.

(* The Round-2 trace must be independent of (share, nonces). The       *)
(* binding factor rho_i and challenge c are derived from public         *)
(* inputs (commits, msg) and are therefore public; lambda_i is          *)
(* a public function of the quorum index set.                           *)

declare axiom round2_constant_time
      (share1 share2 : share_t)
      (n1 n2 : nonce_pair_t)
      (sess : session_t)
      (my_idx : int)
      (commits : commit_list_t)
      (msg : message_t) :
    equiv [ R2.round2 ~ R2.round2 :
              ={sess, my_idx, commits, msg}
              /\ share{1} = share1 /\ share{2} = share2
              /\ nonces{1} = n1 /\ nonces{2} = n2
            ==>
              res{1}.`2 = res{2}.`2 ].

end section Round2CT.

(* -------------------------------------------------------------------- *)
(* Combine: trivially CT (no secret inputs)                              *)
(* -------------------------------------------------------------------- *)
(* No lemma needed — the routine touches only public Round-1 and        *)
(* Round-2 messages plus the group public key.                          *)

(* -------------------------------------------------------------------- *)
(* End of FROST_CT.ec                                                    *)
(* -------------------------------------------------------------------- *)
