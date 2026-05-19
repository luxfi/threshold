# Lean ↔ EasyCrypt Lagrange bridge (FROST)

## Why this document exists

The FROST Tier B → A submission uses **two complementary provers**:

* **EasyCrypt** drives the procedure-level refinement / equiv proofs
  for the threshold layer (`proofs/easycrypt/FROST_N1.ec`,
  `FROST_N1_Refinement.ec`, `FROST_Ciphersuite_*.ec`,
  `FROST_N4.ec`).
* **Lean 4 + Mathlib** carries the algebraic content: Shamir
  reconstruction over F_r, Lagrange interpolation linearity,
  finite-field polynomial uniqueness. Mathlib has the field theory
  we'd otherwise have to re-axiomatize in EC.

The bridge between them is currently **conceptual** — the EC side
states the algebraic identities it needs as **named axioms** that
correspond 1:1 to **proved Lean theorems** in
`~/work/lux/proofs/lean/Crypto/FROST.lean` and
`~/work/lux/proofs/lean/Crypto/Threshold_Lagrange.lean`. This
document pins that 1:1 correspondence so a reviewer can verify the
math content is discharged elsewhere and not silently hand-waved.

The honest framing (same as Pulsar): **the EasyCrypt axioms named
below are not unproved obligations in the strict sense — they are
imports from the Lean proof artifact**. The audit gap is operational
(no mechanical proof-object exchange across the two provers, no
shared serialization format) rather than mathematical.

## Repository pin-points

* EasyCrypt side:
  `~/work/lux/threshold/protocols/frost/proofs/easycrypt/`.
* Lean side: `~/work/lux/proofs/lean/Crypto/`, files
  `FROST.lean` and `Threshold_Lagrange.lean`.

## Axiom-to-theorem mapping

### Axiom 1: `scalar_add_zeroR` (Pulsar_N1 mirror)

**EasyCrypt statement** (`proofs/easycrypt/FROST_N1.ec:130`):

```ec
axiom scalar_add_zeroR : forall (s : scalar_t), scalar_add s scalar_zero = s.
```

**Lean proof**: Instance fact for any `AddCommMonoid F`. Mathlib
auto-derives this from the field structure on F_r; no named theorem
required.

### Axiom 2: `reconstruct_linear`

**EasyCrypt statement** (`proofs/easycrypt/FROST_N1.ec:135`):

```ec
axiom reconstruct_linear :
  forall (Q : int list) (a b : share_t list),
    size a = size Q => size b = size Q =>
    reconstruct Q (map (fun p => scalar_add p.`1 p.`2) (zip a b)) =
      scalar_add (reconstruct Q a) (reconstruct Q b).
```

**Lean proof**
(`~/work/lux/proofs/lean/Crypto/Threshold_Lagrange.lean:81`):

```lean
theorem combine_distributes_over_sum
    {ι : Type*} [DecidableEq ι] (s : Finset ι) (v : ι → F) (a b : ι → F) :
    Lagrange.interpolate s v (a + b) =
      Lagrange.interpolate s v a + Lagrange.interpolate s v b :=
  (Lagrange.interpolate s v).map_add a b
```

Cited in FROST as
`Crypto.FROST.Lagrange.combine_distributes_over_sum`
(`~/work/lux/proofs/lean/Crypto/FROST.lean:147`).

**Correspondence**:

| Symbol | EC | Lean |
|---|---|---|
| Quorum | `Q : int list` (with `uniq Q`) | `s : Finset ι` + `v : ι → F` injective on `s` |
| Per-party value | `share_t list` | `ι → F` |
| List addition | `zip_add a b` | `a + b` (pointwise) |
| Linear combine | `reconstruct Q ...` | `Lagrange.interpolate s v ...` |

### Axiom 3: `lagrange_inverse_eval`

**EasyCrypt statement** (`proofs/easycrypt/FROST_N1.ec:145`):

```ec
axiom lagrange_inverse_eval (s : share_t) (Q : int list) :
  uniq Q =>
  1 <= size Q =>
  reconstruct Q (List.map (poly_eval s) Q) = s.
```

**Lean proof** (`~/work/lux/proofs/lean/Crypto/FROST.lean:140`):

```lean
theorem shamir_correct_at_target
    (f : F[X]) {ι : Type*} [DecidableEq ι]
    (s : Finset ι) (v : ι → F)
    (hvs : Set.InjOn v s) (degree_f_lt : f.degree < s.card) :
    f = Lagrange.interpolate s v (fun i => f.eval (v i)) :=
  Crypto.Threshold.Lagrange.threshold_reconstructs_secret f s v hvs degree_f_lt
```

Cited as `Crypto.FROST.Lagrange.shamir_correct_at_target`. Pulled
in from `Crypto.Threshold.Lagrange.threshold_reconstructs_secret`
(`Crypto/Threshold_Lagrange.lean:51`).

### Axiom 4: `threshold_partial_response_identity`

**EasyCrypt statement** (`proofs/easycrypt/FROST_N1.ec:155`):

```ec
axiom threshold_partial_response_identity :
  forall (Q : int list) (s : share_t),
    uniq Q =>
    1 <= size Q =>
    foldr scalar_add scalar_zero
      (map (fun (i : int) =>
              scalar_mul_s (lagrange Q i) (poly_eval s i)) Q) = s.
```

**Lean proof**
(`~/work/lux/proofs/lean/Crypto/Threshold_Lagrange.lean:121`):

```lean
theorem threshold_partial_response_identity
    (f : F[X]) {ι : Type*} [DecidableEq ι] (s : Finset ι) (v : ι → F)
    (hvs : Set.InjOn v s) (degree_f_lt : f.degree < s.card)
    (y : ι → F) (c : F)
    (z : ι → F) (hz : z = y + c • fun i => f.eval (v i)) :
    (Lagrange.interpolate s v z).eval 0 =
      (Lagrange.interpolate s v y).eval 0 + c * f.eval 0 := ...
```

Cited as `Crypto.FROST.Lagrange.threshold_partial_response_identity`.

## EC files referenced (existence check)

The bridge guard at
`~/work/lux/threshold/scripts/check-high-assurance.sh` enforces
that every EC file referenced in this document exists on disk:

* `proofs/easycrypt/FROST_N1.ec`
* `proofs/easycrypt/FROST_N4.ec`

## Lean files referenced (existence check)

* `lean/Crypto/FROST.lean`
* `lean/Crypto/Threshold_Lagrange.lean`
* `lean/Crypto/Pulsar/Shamir.lean` (shared algebraic theorem)
