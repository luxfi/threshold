# Cross-family defense in depth

Why **Aurora** (Pulsar ‖ Corona) and **Nova** (Pulsar ‖ Corona ‖
Magnetar) name distinct profiles, and why the third leg matters.

## Lattice-family inclusion

Module-LWE with module rank `k=1` *is* Ring-LWE. There are
polynomial-time reductions between them with parameter shifts in
modulus and error width. Stacking Pulsar (MLWE) and Corona (RLWE)
gives:

- Implementation-level diversity (different code, parameter sets,
  rejection samplers, DKG ceremonies).
- NOT family-disjoint hardness — a structural break against lattice
  cryptography compromises both.

**Aurora** is named after a single-cause event, not a redundancy
construction: both lattice-family events that could trigger it share
a common cause.

## What hash adds

**Magnetar** (FIPS 205 / SLH-DSA, public-DKG + MPC) rests on hash
collision and preimage resistance, not on any lattice assumption.
A polynomial-time MLWE oracle does not yield a hash-collision oracle,
and vice-versa. Cross-family disjointness:

- MLWE break → compromises Pulsar AND Corona.
- Hash break → compromises Magnetar AND every hash-anchored primitive
  in the stack (SHA-3, BLAKE3, Merkle trees, …) — but Pulsar and
  Corona survive.

Either failure leaves at least one of the three primitives standing.
**Nova safety property.**

## Production stages

1. **Stage A — GPU batch verify of single-party SLH-DSA** (live).
   Nova gates on a batch of per-validator SLH-DSA sigs verified through
   one `LatticeOps.SLHDSAVerifyBatch` dispatch. Throughput bounded by
   N · (single-party SLH-DSA verify), amortised by GPU.
2. **Stage B — Pedersen-DKG + MPC threshold SLH-DSA** (slot `0x012207`
   in LP-0120, in cryptographic review). Nova collapses to a single
   threshold-SLH-DSA cert. Lineage: Goyal–Kothapalli–Masny–Mukherjee
   IACR 2024/447 + Pedersen-VSS auditability layer.

A code-family threshold scheme (HQC, NIST PQC4 backup KEM) is
research-track only; HQC is a KEM, code-based signature schemes (CFS,
SDP-based) are not NIST-tier. Magnetar is the third leg; Nova safety
holds whether Stage A or Stage B is active.

## Wire impact

```
Profile         Construction                       Per-block wire
──────────      ─────────────────────────────────  ──────────────
Pulsar          Module-LWE threshold (floor)         ~3.3 KB
Aurora          Pulsar ‖ Corona                      ~36 KB
Nova (Stage A)  Pulsar ‖ Corona ‖ Magnetar           ~36 KB + N × 35.7 KB
                  (N = signing committee, batched verify)
Nova (Stage B)  Pulsar ‖ Corona ‖ Magnetar           ~36 KB + 35.7 KB
                  (single MPC threshold SLH-DSA, slot 0x012207)
```

Stage A is heavy (third leg = N per-validator SLH-DSA sigs batched at
verify time). Stage B brings it down to a single threshold-SLH-DSA cert;
verifier ABI unchanged (standard FIPS 205 verifier).

## See also

- [LP-0120](../../lps/LPs/lp-0120-quasar-mainnet-defaults.md) — Quasar
  mainnet defaults + strict-PQ profile gate.
- [magnetar.md](magnetar.md) — protocol detail (Pedersen-DKG + MPC + GPU batch).
- [README.md](README.md) — comparative index.
