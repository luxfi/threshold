(* -------------------------------------------------------------------- *)
(* CGGMP21 -- ZK subprotocol cluster                                    *)
(* -------------------------------------------------------------------- *)
(* STATUS: SHELL.                                                       *)
(*                                                                      *)
(* CGGMP21 uses 17 distinct zero-knowledge subprotocols (see              *)
(* `~/work/lux/threshold/pkg/zk/`):                                      *)
(*   1. ZK_LOG_PAILLIER       — Paillier-encrypted log knowledge         *)
(*   2. ZK_LOG_PEDERSEN       — Pedersen log knowledge                  *)
(*   3. ZK_EQ_LOG             — Equality of two logs                    *)
(*   4. ZK_AFFINE             — Affine relation (ax + b = y)            *)
(*   5. ZK_MTA                — MtA knowledge proof                     *)
(*   6. ZK_MTA_AWC            — MtA "absent witness check"               *)
(*   7. ZK_RANGE              — Range proof in Z                        *)
(*   8. ZK_RANGE_AND          — Range conjunction                       *)
(*   9. ZK_MOD                — Modulus correctness                     *)
(*  10. ZK_MOD_BLUM           — Paillier-Blum biprime soundness         *)
(*  11. ZK_PRM                — Pedersen-parameters knowledge           *)
(*  12. ZK_FAC                — Factoring knowledge                     *)
(*  13. ZK_DEC                — Decryption-key knowledge                *)
(*  14. ZK_ELOG               — ElGamal log knowledge                   *)
(*  15. ZK_ENC                — Encryption knowledge                    *)
(*  16. ZK_PRESIG             — Presignature consistency                *)
(*  17. ZK_REFRESH            — Refresh-soundness                       *)
(*                                                                      *)
(* Each subprotocol provides:                                           *)
(*   - Completeness: honest prover convinces honest verifier            *)
(*   - Soundness: cheating prover convinces verifier with prob <= 2^-s  *)
(*   - Zero-knowledge: simulator exists that produces                   *)
(*     statistically-indistinguishable transcripts                       *)
(*                                                                      *)
(* This file states the obligation surface; per-subprotocol             *)
(* mechanization is multi-month work (each ZK is itself a substantial   *)
(* refinement).                                                          *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool DInterval SmtMap.

type statement_t.
type witness_t.
type transcript_t.

(* ZK protocol triple (Prove, Verify, Simulate).                        *)
module type ZKProtocol = {
  proc prove(stmt : statement_t, witn : witness_t) : transcript_t
  proc verify(stmt : statement_t, t : transcript_t) : bool
  proc simulate(stmt : statement_t) : transcript_t
}.

(* -------------------------------------------------------------------- *)
(* ZK security obligations                                              *)
(* -------------------------------------------------------------------- *)

section ZKSecurity.

declare module Z <: ZKProtocol.

(* Completeness: prove-then-verify always succeeds on valid             *)
(* (statement, witness) pairs.                                           *)
declare axiom zk_completeness :
  forall (stmt : statement_t) (witn : witness_t),
    True.  (* equiv [ Z.prove ~~~ Z.verify(stmt,_): res = true ]       *)

(* Soundness: any prover P that produces verifying transcripts on       *)
(* statements without witnesses succeeds with prob <= 2^-statistical.   *)
declare axiom zk_soundness :
  forall (stmt : statement_t),
    True.  (* Probabilistic statement; concrete form lives in CGGMP21.*)

(* Zero-knowledge: simulator's transcript distribution is               *)
(* statistically-indistinguishable from the real transcript             *)
(* distribution under any (stmt, witn).                                  *)
declare axiom zk_zero_knowledge :
  forall (stmt : statement_t) (witn : witness_t),
    True.  (* equiv [ Z.prove ~ Z.simulate : ={stmt} ==> ={res} ]      *)

end section ZKSecurity.

(* -------------------------------------------------------------------- *)
(* Per-subprotocol obligation registry                                  *)
(* -------------------------------------------------------------------- *)
(* Each of the 17 ZK subprotocols in `~/work/lux/threshold/pkg/zk/`     *)
(* should have its own module declaration here (or its own EC file     *)
(* under `lemmas/zk_*.ec`). At Tier B shell stage we enumerate the      *)
(* obligation count but do not unfold each protocol. The closure path  *)
(* is documented in `AXIOM-INVENTORY.md`.                                *)
(* -------------------------------------------------------------------- *)

(* The 17 ZK protocols above all share the same completeness /          *)
(* soundness / ZK obligation shape. Mechanizing one (e.g., ZK_MTA)      *)
(* gives a template for the other 16.                                   *)

(* -------------------------------------------------------------------- *)
(* End of CGGMP21_ZK.ec                                                  *)
(* -------------------------------------------------------------------- *)
