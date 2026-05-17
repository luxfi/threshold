# Comet — hash-based PQ tier

Comet is the hash-only branch of the Lux PQ-threshold study.
Structurally, it is **different** from Pulsar and Corona: those are
two-round FSwA-style threshold constructions over R_q / R_q^k, where
the Lagrange-linearity of polynomial-vector sums gives an aggregate
that is byte-equal to a single-party signature. SLH-DSA (FIPS 205)
admits no such construction — the signing tree is hash-anchored and
each per-leaf WOTS+ chain is one-time-use.

This document explains what currently ships as "Comet" and what
remains research-track work.

## What ships today

- **GPU-accelerated batch verification** of single-party SLH-DSA
  signatures. Used by QuasarCert's `MLDSARollup` verifier path to
  amortise N per-validator-sig verifies across a single dispatch.

  - `luxfi/crypto v1.19.2` — `slhdsa.VerifyBatch` (CPU fallback) and
    `slhdsa.VerifyBatchGPU` (GPU dispatch).
  - `luxfi/accel v1.1.0` — `LatticeOps.SLHDSAVerifyBatch` dispatch
    point (despite the namespace, this method is hash-based; the
    naming follows the umbrella PQ-batch interface).
  - `luxcpp/accel v0.1.1` — Metal / CUDA GPU kernels for the batch
    SLH-DSA verifier. The CPU fallback path is at parity with the
    standard FIPS 205 single-party verifier; the GPU path
    parallelises the per-leaf hash-chain traversals across an array
    of independent (pk, msg, sig) triples.

- **Soundness property of the batch dispatcher**: every triple in an
  accepted batch is *individually* verifiable. There is no
  averaging-of-trust effect — failure of any single triple poisons
  the batch. Stated as `comet_batch_sound` in `proofs/lean/Crypto/
  Comet.lean`.

- **Cross-family disjointness**: a polynomial-time MLWE / RLWE attack
  does not by itself break SLH-DSA. Stated as
  `comet_hash_disjoint_from_mlwe` / `_rlwe` (axiomatic).

## What's research-track

A *true* threshold variant of SLH-DSA — where t-of-n parties
collaborate to produce a single signature byte-equal to (or at least
verifier-compatible with) standard FIPS 205 — is not currently
shipped. The published designs to start from:

- Goyal–Kothapalli–Masny–Mukherjee (IACR 2024/447), *"Practical
  Threshold SPHINCS+"*. The proposed protocol uses a fresh
  HORST/FORS leaf per signing session and a distributed dealer-free
  setup. Block size ≥ standard SLH-DSA; per-validator rounds and
  trust model differ.
- IRTF / CFRG threshold-friendly hash-based signature drafts (still
  in flux as of mid-2026).

A true threshold-Comet is reserved for precompile slot **0x012207**
in LP-0120 §4. Until a backend is wired, that slot stays a paper
reservation, not a shipped artifact.

## Where it fits in QuasarCert

```
QuasarCert (per-block envelope)
├── BLS aggregate          — classical fast lane, 48 B
├── Pulsar threshold cert  — Module-LWE PQ floor, 3.3 KB
└── (profile) MLDSARollup  — per-validator identity sigs,
                              verified via Comet GPU batch dispatch
                              (single-party SLH-DSA, n triples,
                              one accel.LatticeOps.SLHDSAVerifyBatch
                              call)
```

When the strict-PQ Magnetar profile (`Pulsar ‖ Corona ‖ Comet`) is
enabled, the third leg currently means **the batch-verify path
through Comet**, not a true threshold-SLH-DSA cert. The naming is
intentional: the precompile slot reservation makes the eventual
threshold variant a drop-in upgrade.

## Files

- `~/work/lux/crypto/slhdsa/` — single-party SLH-DSA + GPU batch verify
- `~/work/lux/accel/` (and luxcpp/accel) — GPU kernels
- `~/work/lux/proofs/lean/Crypto/Comet.lean` — Lean structural proof
- `~/work/lux/lps/LPs/lp-0120-quasar-mainnet-defaults.md` — slot
  reservation + Magnetar profile

## Honest accounting

What is **not** claimed:
- That Comet today provides a threshold cryptographic guarantee
  parallel to Pulsar / Corona.
- That the per-validator identity sigs in `MLDSARollup` are
  thresholdized — they are individual signatures, batch-verified
  for amortisation only.

What **is** claimed:
- GPU batch verify is sound and complete with respect to standard
  FIPS 205 single-party verify (`comet_batch_sound` /
  `comet_batch_complete`).
- The hash-only hardness substrate is disjoint from MLWE / RLWE, so
  including Comet in the Magnetar profile gives *cross-family*
  defense in depth even at the batch-verify-only tier.
