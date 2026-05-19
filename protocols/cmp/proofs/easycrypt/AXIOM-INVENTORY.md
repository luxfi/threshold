# CGGMP21 EasyCrypt axiom inventory

> Honest enumeration of every `axiom` and `admit` in the CGGMP21 EC
> theories. Mirrors `~/work/lux/pulsar/AXIOM-INVENTORY.md` structure.

## Status

| Category | Count |
|---|---|
| Lean-bridged algebraic axioms (Lagrange / Paillier) | 6 |
| Section-local declared axioms (byte-walk, ZK) | 4 |
| Refinement-obligation axioms (presign R1/R2/R3 + sign vs honest spec) | 4 |
| CT obligations (concrete-impl-dependent declared axioms) | 4 |
| `admit`s in proof bodies | 1 |

## Lean-bridged axioms (6)

### Lagrange / Shamir over F_n (4)

| # | EC axiom | EC file:line | Lean theorem | Lean file |
|---|---|---|---|---|
| 1 | `scalar_add_zeroR` | `CGGMP21_N1.ec:120` | `AddCommMonoid` instance | (Mathlib auto-derived) |
| 2 | `reconstruct_linear` | `CGGMP21_N1.ec:125` | `combine_distributes_over_sum` | `Crypto/Threshold_Lagrange.lean:81` |
| 3 | `lagrange_inverse_eval` | `CGGMP21_N1.ec:135` | `shamir_correct_at_target` | `Crypto/Pulsar/Shamir.lean:76` |
| 4 | `derive_pk_homomorphism` (N4) | `CGGMP21_N4.ec:64` | `derive_pk_homomorphism` | `Crypto/CGGMP21.lean` (Lux profile extension) |

### Paillier algebra (2)

| # | EC axiom | EC file:line | Lean theorem | Lean file |
|---|---|---|---|---|
| 5 | `paillier_add_homomorphism` | `CGGMP21_Paillier.ec:56` | `paillier_add_homomorphism` | `Crypto/CGGMP21.lean:200` |
| 6 | `paillier_scalar_homomorphism` | `CGGMP21_Paillier.ec:69` | `paillier_mul_homomorphism` | `Crypto/CGGMP21.lean:212` |

## Section-local declared axioms (4)

The Combine/Sign byte-walk axiom mirrors Pulsar's
`combine_body_compute_sig_spec`. The three ZK security axioms
(`zk_completeness`, `zk_soundness`, `zk_zero_knowledge`) are
parameterized over the 17 ZK subprotocols in
`~/work/lux/threshold/pkg/zk/`.

| # | EC axiom | EC file:line | Discharge target |
|---|---|---|---|
| 7 | `cggmp21_dispatches_to_ecdsa` | `CGGMP21_N1.ec:218` | `jasmin/{presign,sign}/` extraction |
| 8 | `zk_completeness` | `CGGMP21_ZK.ec:62` | Per-protocol completeness (17 subprotocols) |
| 9 | `zk_soundness` | `CGGMP21_ZK.ec:69` | Per-protocol soundness (17 subprotocols) |
| 10 | `zk_zero_knowledge` | `CGGMP21_ZK.ec:77` | Per-protocol ZK simulator (17 subprotocols) |

## Refinement-obligation axioms (4)

Stated as deferred obligations in `CGGMP21_N1_Refinement.ec`. The
presign refinement is gated on a libjade-port-of-Paillier; the sign
refinement is the simpler one-line scalar arithmetic step.

| # | EC axiom | EC file:line | Discharge target |
|---|---|---|---|
| 10a | `presign_round1_refinement_axiom` | `CGGMP21_N1_Refinement.ec:115` | `jasmin/presign/round1.jazz` |
| 10b | `presign_round2_refinement_axiom` | `CGGMP21_N1_Refinement.ec:144` | `jasmin/presign/round2.jazz` |
| 10c | `presign_round3_refinement_axiom` | `CGGMP21_N1_Refinement.ec:161` | `jasmin/presign/round3.jazz` |
| 10d | `sign_online_refinement_axiom` | `CGGMP21_N1_Refinement.ec:175` | `jasmin/threshold/sign_online.jazz` |

## CT obligations (4)

| # | EC axiom | EC file:line | Discharge target |
|---|---|---|---|
| 11 | `presign_round1_constant_time` | `lemmas/CGGMP21_CT.ec:73` | `jasmin/presign/round1.jazz` |
| 12 | `presign_round2_constant_time` | `lemmas/CGGMP21_CT.ec:93` | `jasmin/presign/round2.jazz` (Paillier dec) |
| 13 | `presign_round3_constant_time` | `lemmas/CGGMP21_CT.ec:113` | `jasmin/presign/round3.jazz` |
| 14 | `sign_online_constant_time` | `lemmas/CGGMP21_CT.ec:132` | `jasmin/threshold/sign_online.jazz` |

## `admit`s (1)

| # | Location | Closure |
|---|---|---|
| 15 | `CGGMP21_N4.ec` `cggmp21_n4_pk_preservation_honest` | Same one-line group-identity rewrite as FROST_N4 / Pulsar_N4. Closure: add `derive_pk_group_identity` to `Crypto.CGGMP21.lean`. |

## Closure roadmap

- **Axioms 1-4 (Lagrange)**: Closed in Lean, bridged via the
  high-assurance gate.
- **Axioms 5-6 (Paillier)**: Stated in EC; mechanizable in Lean
  via Mathlib's commutative-ring tactic + CRT machinery. Estimated
  4-6 weeks Lean work.
- **Axiom 7 (byte-walk)**: Discharged Jasmin-side once the
  presign+sign extraction lands.
- **Axioms 8-10 (ZK)**: Each of the 17 ZK subprotocols requires
  its own EC theory (completeness + soundness + ZK simulator).
  Estimated 3-6 months per subprotocol; the cluster is a Tier A
  multi-year program (the same scale as the `lurk-rs` /
  `arkworks` foundational ZK formal-methods program).
- **Axioms 11-14 (CT)**: Discharged by `jasminc -checkCT` on the
  threshold-layer Jasmin sources.
- **Admit 15**: One-line Lean lemma.
