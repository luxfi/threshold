# BLS-Threshold EasyCrypt axiom inventory

> Honest enumeration of every `axiom` and `admit` in the BLS-threshold
> EC theories. Mirrors `~/work/lux/pulsar/AXIOM-INVENTORY.md` structure.

## Status

| Category | Count |
|---|---|
| Lean-bridged algebraic axioms (Lagrange / Shamir / G1-G2) | 6 |
| Section-local declared axioms (byte-walk) | 1 |
| Refinement-obligation axioms (aggregate vs spec) | 1 |
| Spec-level support axioms (aggregate_g2_spec) | 1 |
| CT obligations (concrete-impl-dependent declared axioms) | 1 |
| `admit`s in proof bodies | 1 |

BLS-threshold has the smallest formal-methods surface of the three
classical threshold protocols (FROST, CGGMP21, BLS) — there is no
nonce sampling, no MtA, no ZK cluster, no Paillier. The byte-walk
reduces to a single line: the encoded sum of lambda_i * sigma_i
equals the encoded H(m)^{f(0)}.

## Lean-bridged axioms (6)

### Lagrange / Shamir over F_r (3)

| # | EC axiom | EC file:line | Lean theorem | Lean file |
|---|---|---|---|---|
| 1 | `scalar_add_zeroR` | `BLS_Threshold_N1.ec:127` | `AddCommMonoid` instance | (Mathlib auto-derived) |
| 2 | `reconstruct_linear` | `BLS_Threshold_N1.ec:131` | `combine_distributes_over_sum` | `Crypto/Threshold_Lagrange.lean:81` |
| 3 | `lagrange_inverse_eval` | `BLS_Threshold_N1.ec:140` | `shamir_correct_at_target` | `Crypto/Pulsar/Shamir.lean:76` |

### G1/G2 group structure (3)

| # | EC axiom | EC file:line | Lean theorem | Lean file |
|---|---|---|---|---|
| 4 | `threshold_lagrange_identity` | `BLS_Threshold_N1.ec:148` | `threshold_partial_response_identity` (no-y-mask form) | `Crypto/Threshold_Lagrange.lean:121` |
| 5 | `g2_scalar_mul_distributes` | `BLS_Threshold_N1.ec:172` | `Crypto.BLS.Threshold.g2_scalar_mul_distributes_over_sum` | `Crypto/BLS.lean` (Lux profile extension) |
| 6 | `derive_pk_homomorphism` (N4) | `BLS_Threshold_N4.ec:73` | `Crypto.BLS.Threshold.derive_pk_homomorphism` | `Crypto/BLS.lean` |

## Section-local declared axioms (1)

| # | EC axiom | EC file:line | Discharge target |
|---|---|---|---|
| 7 | `bls_threshold_dispatches_to_bls` | `BLS_Threshold_N1.ec:213` | `jasmin/threshold/aggregate.jazz` extraction OR pure-Go proof against `luxfi/crypto/bls` |

## Refinement-obligation axioms (1) + Spec-level support (1)

| # | EC axiom | EC file:line | Discharge target |
|---|---|---|---|
| 7a | `aggregate_refinement_axiom` | `BLS_Threshold_N1_Refinement.ec:88` | Standard EC `while`-to-foldr rewrite; closable in v1.8.1 |
| 7b | `aggregate_g2_spec` | `BLS_Threshold_N1_Refinement.ec:69` | Pure definitional unfolding of `aggregate_g2` |

## CT obligations (1)

| # | EC axiom | EC file:line | Discharge target |
|---|---|---|---|
| 8 | `partial_sign_constant_time` | `lemmas/BLS_Threshold_CT.ec:33` | `cloudflare/circl/ecc/bls12381` G2 scalar mul CT |

## `admit`s (1)

| # | Location | Closure |
|---|---|---|
| 9 | `BLS_Threshold_N4.ec` `bls_threshold_n4_pk_preservation_honest` | Same one-line group-identity rewrite as FROST_N4 / CGGMP21_N4 / Pulsar_N4. |

## Closure roadmap

- **Axioms 1-3 (Lagrange / Shamir over F_r)**: Already closed in
  Lean via `Crypto.Threshold.Lagrange`.
- **Axiom 4 (threshold response identity)**: Closed in Lean
  (special case of `threshold_partial_response_identity` with the
  y-mask vector set to zero).
- **Axioms 5-6 (G1/G2 distributivity)**: Stated as Lean axioms in
  the existing `Crypto.BLS` module; provable from Mathlib's
  abelian-group machinery once BLS12-381 G1/G2 are formally
  modeled (no native Mathlib BLS12-381 module yet).
- **Axiom 7 (byte-walk)**: Single-line refinement; closable in
  EC directly without Jasmin extraction (the algebraic content is
  already captured by Axioms 4-6 + the encode_g2 inverse).
- **Axiom 8 (CT)**: Inherits from circl's documented CT story.
- **Admit 9**: One-line Lean lemma.
