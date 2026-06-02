# Lux PQ-threshold comparative study

Three post-quantum primitives ship in the Lux Quasar consensus stack
as "threshold authentication".

| Primitive | Lane | Construction | Hardness |
|---|---|---|---|
| **Pulsar** | Module-LWE threshold | 2-round FSwA-style threshold ML-DSA (FIPS 204 byte-equal); public DKG | MLWE + MSIS |
| **Corona** | Ring-LWE threshold | 2-round Ring-LWE threshold over R_q; public DKG | RLWE |
| **Magnetar** | Hash-family threshold | Public-DKG + Pedersen VSS + MPC threshold SLH-DSA (FIPS 205 byte-equal); GPU-batched single-party verify for amortisation | Hash collision + preimage |

Pulsar and Corona share lattice + Lagrange-over-F_q scaffolding.
Magnetar is structurally different — SLH-DSA's signing tree is
hash-anchored; no Lagrange-linearity threshold construction admits.
Magnetar combines public DKG with MPC evaluation of the SLH-DSA tree
(GKMM 2024/447 + Pedersen-VSS auditability); the MPC output is
byte-equal to a standard FIPS 205 signature.

## Files

| File | Topic |
|---|---|
| [pulsar.md](pulsar.md) | Threshold ML-DSA |
| [corona.md](corona.md) | Threshold Ring-LWE |
| [magnetar.md](magnetar.md) | Public-DKG MPC threshold SLH-DSA + hash-tier |
| [cross-family-defense.md](cross-family-defense.md) | Aurora (P‖C) vs Nova (P‖C‖M) cert-profile naming |

## Why three, not one

Different performance / size envelopes, different hardness assumptions:

```
Sig size            Verify (CPU)         Hardness family
─────────           ─────────────        ───────────────
Pulsar    3.3 KB    181 µs / 3 µs cached   Module-LWE (lattice, FIPS 204)
Corona     33 KB    1.6 ms                 Ring-LWE   (lattice, R_q)
Magnetar  35.7 KB   1.9 ms / 131 µs cached Hash family (FIPS 205)
                                            * single-party SLH-DSA;
                                              GPU batch path amortises
                                              N verifies into ~1 dispatch.
                                            * threshold-MPC signing
                                              lands at LP-0120 0x012207.
```

Pulsar = floor (fastest, smallest, FIPS-validated). Corona = intra-
lattice diversity. Magnetar = cross-family diversity; a structural
break against MLWE/RLWE leaves it standing.

## Cross-reference

- **Lean proofs**:
  - `proofs/lean/Crypto/Pulsar/{Shamir,Unforgeability,OutputInterchange,dkg2}.lean`
  - `proofs/lean/Crypto/Corona.lean`
  - `proofs/lean/Crypto/Magnetar.lean`
  - All build under `lake build Crypto`.
- **Papers**:
  - `papers/lp-073-pulsar/lp-073-pulsar.tex`
  - `papers/lux-corona-pq/lux-corona-pq.tex`
  - `papers/lp-074-magnetar/` — open.
- **Go implementations**:
  - `~/work/lux/pulsar/` + `~/work/lux/pulsar-mptc/` (NIST MPTC)
  - `~/work/lux/corona/`
  - `~/work/lux/crypto/slhdsa/` (single-party + batch verify)
  - `~/work/lux/threshold/protocols/magnetar/` (Pedersen-DKG + MPC, in flight)
- **Threshold library (this repo)**:
  - `protocols/corona/`, `protocols/bls/`, `protocols/cmp/`,
    `protocols/frost/`, `protocols/doerner/`.

## See also

- [LP-0120](../../lps/LPs/lp-0120-quasar-mainnet-defaults.md) — Quasar
  mainnet defaults + **Aurora** / **Nova** cert profiles.
- [LP-105](../../lps/LP-105-lux-stack-lexicon.md) — naming policy.
- [proofs/lean/Crypto/](../../proofs/lean/Crypto/) — Lean proof tree.
