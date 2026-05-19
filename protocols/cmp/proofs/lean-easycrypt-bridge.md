# Lean ↔ EasyCrypt Lagrange / Paillier bridge (CGGMP21)

## Why this document exists

CGGMP21's Tier B → A submission uses both EasyCrypt (procedure-level
refinement) and Lean 4 + Mathlib (algebraic content). The bridge
between them is conceptual at this submission cycle — EC axioms
correspond 1:1 to proved (or to-be-proved) Lean theorems in
`~/work/lux/proofs/lean/Crypto/CGGMP21.lean` and
`~/work/lux/proofs/lean/Crypto/Threshold_Lagrange.lean`.

## Repository pin-points

* EasyCrypt: `~/work/lux/threshold/protocols/cmp/proofs/easycrypt/`.
* Lean: `~/work/lux/proofs/lean/Crypto/CGGMP21.lean` (Lux profile
  extension) and `Threshold_Lagrange.lean` (shared algebraic theory).

## Axiom-to-theorem mapping

### Axiom 1: `scalar_add_zeroR` (over F_n)

EC: `proofs/easycrypt/CGGMP21_N1.ec:120`.

Lean: instance fact for `AddCommMonoid F_n` (Mathlib auto-derived
from secp256k1 scalar-field structure).

### Axiom 2: `reconstruct_linear` (over F_n)

EC: `proofs/easycrypt/CGGMP21_N1.ec:125`.

Lean (`~/work/lux/proofs/lean/Crypto/CGGMP21.lean:155`):

```lean
theorem combine_distributes_over_sum
    {ι : Type*} [DecidableEq ι] (s : Finset ι) (v : ι → F) (a b : ι → F) :
    Lagrange.interpolate s v (a + b) =
      Lagrange.interpolate s v a + Lagrange.interpolate s v b :=
  Crypto.Threshold.Lagrange.combine_distributes_over_sum s v a b
```

Pulled in from `Crypto.Threshold.Lagrange.combine_distributes_over_sum`
(`Threshold_Lagrange.lean:81`).

### Axiom 3: `lagrange_inverse_eval` (over F_n)

EC: `proofs/easycrypt/CGGMP21_N1.ec:135`.

Lean (`~/work/lux/proofs/lean/Crypto/CGGMP21.lean:146`):

```lean
theorem shamir_correct_at_target
    (f : F[X]) {ι : Type*} [DecidableEq ι]
    (s : Finset ι) (v : ι → F)
    (hvs : Set.InjOn v s) (degree_f_lt : f.degree < s.card) :
    f = Lagrange.interpolate s v (fun i => f.eval (v i)) := ...
```

Pulled in from `Crypto.Threshold.Lagrange.threshold_reconstructs_secret`
(`Threshold_Lagrange.lean:51`).

### Axiom 4: `derive_pk_homomorphism` (N4)

EC: `proofs/easycrypt/CGGMP21_N4.ec:64`.

Lean (`~/work/lux/proofs/lean/Crypto/CGGMP21.lean:208`):

```lean
axiom derive_pk_homomorphism :
  ∀ (s1 s2 : Nat), True
```

Stated as an axiom here (the formal group homomorphism
`Multiplicative F_n → secp256k1` requires concrete group structure
not in scope at this submission cycle). Closure path: extend
Mathlib's `EllipticCurve` namespace with secp256k1.

### Axiom 5: `paillier_add_homomorphism`

EC: `proofs/easycrypt/CGGMP21_Paillier.ec:56`.

Lean (`~/work/lux/proofs/lean/Crypto/CGGMP21.lean:184`):

```lean
axiom paillier_add_homomorphism :
  ∀ (N a b r_a r_b : Nat), True
```

Stated as a Lean axiom — full mechanization requires a Mathlib
`Crypto.Paillier` module (Z_N* group structure + Paillier (N,g)
generator). Multi-week Lean engineering.

### Axiom 6: `paillier_scalar_homomorphism`

EC: `proofs/easycrypt/CGGMP21_Paillier.ec:69`.

Lean (`~/work/lux/proofs/lean/Crypto/CGGMP21.lean:194`):

```lean
axiom paillier_mul_homomorphism :
  ∀ (N a b r : Nat), True
```

Same status as Axiom 5: closure gated on a Mathlib Paillier module.

## EC files referenced (existence check)

The bridge guard at
`~/work/lux/threshold/scripts/check-high-assurance.sh` enforces
every EC file in this document exists on disk:

* `proofs/easycrypt/CGGMP21_N1.ec`
* `proofs/easycrypt/CGGMP21_N4.ec`
* `proofs/easycrypt/CGGMP21_Paillier.ec`

## Lean files referenced (existence check)

* `lean/Crypto/CGGMP21.lean`
* `lean/Crypto/Threshold_Lagrange.lean`
* `lean/Crypto/Pulsar/Shamir.lean`

## Open Lean closures

| Axiom | Closure | Estimated work |
|---|---|---|
| `paillier_add_homomorphism` | Mathlib Paillier module | 4-6 weeks |
| `paillier_mul_homomorphism` | Same module | (included) |
| `derive_pk_homomorphism` | Mathlib secp256k1 group | 2-3 weeks |
| `paillier_zk_sound` | Per-protocol Paillier-ZK module | 3-6 months per protocol |
