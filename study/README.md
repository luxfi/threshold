# Lux PQ-threshold comparative study

Three post-quantum primitives ship in the Lux Quasar consensus stack
in the role of "threshold authentication". This directory carries the
comparative study + cross-reference index for the three of them.

| Primitive | Lane | Construction | Hardness |
|---|---|---|---|
| **Pulsar** | Module-LWE threshold | 2-round FSwA-style threshold ML-DSA (FIPS 204 byte-equal) | MLWE + MSIS |
| **Corona** | Ring-LWE threshold | 2-round Ring-LWE threshold over R_q | RLWE |
| **Comet** | Hash-only (batch verify) | GPU-batched single-party SLH-DSA (FIPS 205); a true threshold variant is research-track and reserves precompile slot 0x012207 | Hash collision + preimage resistance |

The first two are structurally similar (lattice + Lagrange interpolation
in F_q) and share substantial protocol scaffolding. The third is
structurally different — SLH-DSA's signing tree is hash-anchored, so
there is no Lagrange-linearity threshold construction the way Pulsar
and Corona admit. What ships as **Comet** today is the GPU-accelerated
batch-verification path; a *true* threshold-SLH-DSA construction would
be a separate research artifact (see `comet.md`).

## Files

| File | Topic |
|---|---|
| [pulsar.md](pulsar.md) | Threshold ML-DSA — protocol, proofs, papers |
| [corona.md](corona.md) | Threshold Ring-LWE — protocol, proofs, papers |
| [comet.md](comet.md) | Hash-based PQ tier — what ships, what's research |
| [cross-family-defense.md](cross-family-defense.md) | Why Aurora (P‖C) and Magnetar (P‖C‖Comet) are the right cert-profile names |

## Why three primitives, not one

The three primitives are not interchangeable; they have different
performance / size envelopes and rest on different cryptographic
hardness assumptions:

```
Sig size           Verify (CPU)         Hardness family
─────────          ─────────────        ───────────────
Pulsar  3.3 KB     181 µs / 3 µs cached    Module-LWE  (lattice, FIPS 204)
Corona  33 KB      1.6 ms                  Ring-LWE    (lattice, R_q)
Comet*  35.7 KB    1.9 ms / 131 µs cached  Hash family (FIPS 205)
                                            * single-party SLH-DSA;
                                              GPU batch path amortises
                                              N verifies into ~1 dispatch
```

Pulsar is the floor (fastest, smallest, FIPS-validated). Corona adds
intra-lattice diversity. Comet adds *cross-family* diversity — a
structural break against MLWE / RLWE leaves Comet standing.

## Cross-reference

- **Lean structural proofs** (mechanized):
  - `proofs/lean/Crypto/Pulsar/{Shamir,Unforgeability,OutputInterchange,dkg2}.lean`
  - `proofs/lean/Crypto/Corona.lean`
  - `proofs/lean/Crypto/Comet.lean`
  - All build under `lake build Crypto`.

- **Papers**:
  - `papers/lp-073-pulsar/lp-073-pulsar.tex`
  - `papers/lux-corona-pq/lux-corona-pq.tex` (file kept legacy name)
  - `papers/lp-073-pulsar/`-style folder for Comet is open.

- **Reference Go implementations**:
  - `~/work/lux/pulsar/` + `~/work/lux/pulsar-mptc/` (NIST MPTC submission)
  - `~/work/lux/corona/`
  - `~/work/lux/crypto/slhdsa/` (single-party SLH-DSA + batch verify)

- **Threshold-protocol library** (this repository):
  - `protocols/corona/` — Ring-LWE threshold protocol library.
  - `protocols/bls/`, `protocols/cmp/`, `protocols/frost/`, `protocols/doerner/`
    cover the classical threshold side of the comparative study.

## See also

- [LP-0120](../../lps/LPs/lp-0120-quasar-mainnet-defaults.md) — Quasar
  mainnet defaults + the Aurora / Magnetar cert-profile names.
- [LP-105](../../lps/LP-105-lux-stack-lexicon.md) — naming policy.
- [proofs/lean/Crypto/](../../proofs/lean/Crypto/) — Lean proof tree
  (all three primitives have entries).
