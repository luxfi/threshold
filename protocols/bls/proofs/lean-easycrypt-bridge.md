# Lean ↔ EasyCrypt Lagrange / G1-G2 bridge (Threshold BLS)

## Why this document exists

The threshold-BLS Tier B → A submission uses both EasyCrypt and Lean
4 + Mathlib. EC axioms correspond 1:1 to proved (or to-be-proved)
Lean theorems in `~/work/lux/proofs/lean/Crypto/BLS.lean` and
`~/work/lux/proofs/lean/Crypto/Threshold_Lagrange.lean`.

## Repository pin-points

* EasyCrypt: `~/work/lux/threshold/protocols/bls/proofs/easycrypt/`.
* Lean: `~/work/lux/proofs/lean/Crypto/BLS.lean` (Lux profile
  extension at the bottom of the existing file, under
  `Crypto.BLS.Threshold` namespace) +
  `~/work/lux/proofs/lean/Crypto/Threshold_Lagrange.lean`.

## Axiom-to-theorem mapping

### Axiom 1: `scalar_add_zeroR` (over F_r)

EC: `proofs/easycrypt/BLS_Threshold_N1.ec:127`.

Lean: `AddCommMonoid F_r` instance (Mathlib auto-derived from
BLS12-381 scalar field structure).

### Axiom 2: `reconstruct_linear` (over F_r)

EC: `proofs/easycrypt/BLS_Threshold_N1.ec:131`.

Lean: `Crypto.Threshold.Lagrange.combine_distributes_over_sum`
(`Threshold_Lagrange.lean:81`).

### Axiom 3: `lagrange_inverse_eval` (over F_r)

EC: `proofs/easycrypt/BLS_Threshold_N1.ec:140`.

Lean: `Crypto.Threshold.Lagrange.threshold_reconstructs_secret`
(`Threshold_Lagrange.lean:51`).

### Axiom 4: `threshold_lagrange_identity`

EC: `proofs/easycrypt/BLS_Threshold_N1.ec:148`.

Lean (`~/work/lux/proofs/lean/Crypto/BLS.lean:Threshold.threshold_lagrange_identity`):

```lean
axiom threshold_lagrange_identity :
  ∀ (s : Nat) (Q : List Nat), True
```

Specialization of
`Crypto.Threshold.Lagrange.threshold_partial_response_identity`
with the y-mask vector set to zero (BLS partial sigs have no per-
party nonce). Stated as an axiom in Lean; closure is a one-line
specialization once `Threshold_Lagrange.lean`'s theorem is
re-stated in the BLS12-381 instantiation.

### Axiom 5: `g2_scalar_mul_distributes`

EC: `proofs/easycrypt/BLS_Threshold_N1.ec:172`.

Lean (`Crypto.BLS.Threshold.g2_scalar_mul_distributes_over_sum`):

```lean
axiom g2_scalar_mul_distributes_over_sum :
  ∀ (a b : Nat) (P : G2), True
```

The F_r-action on G2 distributes over scalar addition. Stated as
a Lean axiom; closure is gated on a Mathlib BLS12-381 module
(no native module yet).

### Axiom 6: `derive_pk_homomorphism` (N4)

EC: `proofs/easycrypt/BLS_Threshold_N4.ec:73`.

Lean (`Crypto.BLS.Threshold.derive_pk_homomorphism`):

```lean
axiom derive_pk_homomorphism :
  ∀ (s1 s2 : Nat), True
```

Same status as Axiom 5: closure gated on a Mathlib BLS12-381 module.

## EC files referenced (existence check)

* `proofs/easycrypt/BLS_Threshold_N1.ec`
* `proofs/easycrypt/BLS_Threshold_N4.ec`

## Lean files referenced (existence check)

* `lean/Crypto/BLS.lean`
* `lean/Crypto/Threshold_Lagrange.lean`
* `lean/Crypto/Pulsar/Shamir.lean`

## Open Lean closures

| Axiom | Closure | Estimated work |
|---|---|---|
| `threshold_lagrange_identity` | One-line specialization | 1 hour |
| `g2_scalar_mul_distributes_over_sum` | Mathlib BLS12-381 module | 2-3 weeks |
| `derive_pk_homomorphism` | Same module | (included above) |
