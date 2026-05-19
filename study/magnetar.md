# Magnetar — Public-DKG MPC Threshold SLH-DSA

Magnetar is the hash-family threshold profile: public-DKG MPC over FIPS
205 SLH-DSA. Pedersen-style VSS makes the DKG transcript publicly
auditable; MPC signing keeps the SLH-DSA secret state distributed and
produces standard-verifier-compatible signatures.

## vs Pulsar

| Property | Pulsar | Magnetar |
|---|---|---|
| Primitive | FIPS 204 ML-DSA (lattice) | FIPS 205 SLH-DSA (hash) |
| Threshold | Algebraic FSwA aggregate | Public-DKG + MPC over signing tree |
| Output | Standard ML-DSA sig | Standard SLH-DSA sig |
| Verifier | FIPS 204 single-party | FIPS 205 single-party |
| Signer cost | Fast (ring/module) | Heavier (hash-chain MPC) |
| Hardness | MLWE + MSIS | Hash collision + preimage |

Both produce standard PQ sigs but sit on disjoint hardness assumptions.
A polynomial-time MLWE/RLWE attack does not break Magnetar; a hash
break does not break Pulsar. Cross-family disjointness is the point of
running both legs in the Nova cert profile.

## Protocol

1. **Public DKG.** Parties jointly generate the SLH-DSA secret seed /
   signing state. No party learns the full secret. Commitments make the
   DKG transcript publicly auditable on-chain.
2. **Pedersen-style VSS.** Each dealer distributes shares; recipients
   verify encrypted shares against Pedersen commitments. Complaints
   are publicly checkable; invalid dealers are deterministically
   disqualified by on-chain quorum logic. Pedersen (hiding) is used
   over Feldman (non-hiding) for public-chain privacy of the secret.
3. **MPC signing.** Qualified parties jointly evaluate SLH-DSA signing.
   The WOTS+ chain state is never reconstructed in one place. Output
   is a byte-equal standard FIPS 205 SLH-DSA signature.
4. **Standard verification.** Standard FIPS 205 verifier; no new
   verifier needed.

## Required properties

DKG is dealer-free (every party contributes; no single party or
sub-threshold quorum can reconstruct or bias the group secret;
Pedersen-VSS complaints disqualify cheaters). DKG outputs a distributed
SLH-DSA secret seed/state. No party can bias the resulting public key
beyond protocol rules (Pedersen binding). Every share is verifiable
against public commitments; invalid shares produce objective complaint
evidence. All honest parties derive the same group public key. `t`
parties can jointly sign; fewer learn nothing useful (Pedersen hiding).
Final signatures verify under the standard FIPS 205 verifier
(byte-equal). Signing never reconstructs the secret. DKG transcript
is domain-separated by chain / session / epoch.

## Ships today

- GPU-accelerated batch verification of single-party SLH-DSA sigs —
  verifier side of Magnetar; used by QuasarCert's `MLDSARollup`
  verifier path to amortise N per-validator-sig verifies into one
  dispatch.
  - `luxfi/crypto v1.19.2` — `slhdsa.VerifyBatch` (CPU) + `VerifyBatchGPU`
  - `luxfi/accel v1.1.0` — `LatticeOps.SLHDSAVerifyBatch` dispatch
    (umbrella PQ-batch interface; the method is hash-based)
  - `luxcpp/accel v0.1.1` — Metal / CUDA / WGSL kernels
- **Batch soundness**: every triple in an accepted batch is individually
  verifiable; failure of any single triple poisons the batch. Stated as
  `magnetar_batch_sound` in `proofs/lean/Crypto/Magnetar.lean`.
- **Sibling rollup proof system — P3Q** (Z-Chain STARK substrate):
  workspace + public surface stable at `v0.0.1`. 10 crates, 43 unit
  tests pass on released types (`ProofBytes`, `ProofSystemId`,
  `P3qError`, Goldilocks field, cSHAKE256 / KMAC256 / TupleHash256,
  Merkle, FRI plumbing, Fiat-Shamir transcript, AIR / STARK trait
  surface, verifier dispatch). Audit-gated proof bodies
  (`p3q-verifier::verify_sha3`, `verify_keccak`, six `p3q-zchain`
  circuits) return typed `P3qError` rather than panicking; production
  verification lands in subsequent `v0.0.x` releases. Strict-PQ-only:
  no KZG, BN254, Groth16, pairings, EC recursion. Same hash family
  (SHA-3 / cSHAKE256) as ML-DSA-65 and Pulsar.
- **Cross-family disjointness**: a polynomial-time MLWE/RLWE attack
  does not by itself break SLH-DSA. Stated as
  `magnetar_hash_disjoint_from_mlwe` / `_rlwe` (axiomatic, justified
  by Goldwasser-Micali-style separation).

## Pending (MPC signing side)

Reference design lineage: Goyal–Kothapalli–Masny–Mukherjee, *Practical
Threshold SPHINCS+* (IACR 2024/447) — dealer-free DKG over WOTS+
seed, per-session HORST/FORS leaf, MPC evaluation of Merkle paths.
Pedersen VSS layer on top of GKMM for hiding-commitment auditability.

Precompile slot **`0x012207`** reserved for the MPC-signed threshold
variant; slot is stable across research-to-production transition.

## Position in QuasarCert

```
QuasarCert (per-block envelope)
├── BLS aggregate          — classical fast lane, 48 B
├── Pulsar threshold cert  — Module-LWE PQ floor, 3.3 KB
└── (profile) MLDSARollup  — per-validator identity sigs verified via
                              Magnetar GPU batch dispatch (single-party
                              SLH-DSA, n triples, one
                              accel.LatticeOps.SLHDSAVerifyBatch call).
                              Threshold MPC SLH-DSA signing upgrade
                              lands at precompile 0x012207 without
                              changing the on-block envelope.
```

When the strict-PQ **Nova** profile (`Pulsar ‖ Corona ‖ Magnetar`) is
enabled, the third leg means the batch-verify path through Magnetar,
plus the MPC-signed threshold SLH-DSA cert once `0x012207` is wired.

## Cert profiles

| Profile | Composition | Lattice break leaves standing |
|---|---|---|
| **Aurora** | Pulsar ∥ Corona | Nothing (both lattice) |
| **Nova** | Pulsar ∥ Corona ∥ Magnetar | Magnetar (hash family) |

`Nova` is the former `Magnetar profile` cert-bundle name; renamed to
avoid colliding with the protocol name.

## Suite identifiers

```
PULSAR-PDKG-THRESHOLD-ML-DSA-65
PULSAR-PDKG-THRESHOLD-ML-DSA-87
MAGNETAR-PDKG-MPC-SLH-DSA-SHAKE-192s
MAGNETAR-PDKG-MPC-SLH-DSA-SHAKE-256s
```

## Files

- `~/work/lux/crypto/slhdsa/` — single-party SLH-DSA + GPU batch verify
- `~/work/lux/accel/` (and luxcpp/accel) — GPU kernels (Metal / CUDA / WGSL)
- `~/work/lux/proofs/lean/Crypto/Magnetar.lean` — Lean structural proof
- `~/work/lux/lps/LPs/lp-0120-quasar-mainnet-defaults.md` — slot
  reservation + Nova cert profile composition
- `~/work/lux/threshold/study/pulsar.md` — sibling lattice-tier
- `~/work/lux/threshold/study/corona.md` — sibling lattice-tier
- `~/work/lux/threshold/study/cross-family-defense.md` — Aurora vs Nova
