# Cross-family defense in depth

Why the Lux Quasar cert-profile naming distinguishes between
**Aurora** (Pulsar ‖ Corona) and **Magnetar** (Pulsar ‖ Corona ‖
Comet), and why the third leg matters.

## The lattice-family inclusion problem

Module-LWE with module rank `k = 1` *is* Ring-LWE. There are
polynomial-time reductions between them with parameter shifts in
modulus and error width. Stacking Pulsar (MLWE) and Corona (RLWE)
gives:

- ✅ Implementation-level diversity (different code, different
  parameter sets, different rejection samplers, different DKG
  ceremonies).
- ❌ NOT family-disjoint hardness — a structural break against
  lattice cryptography compromises both.

This is why the Aurora cert profile (`Pulsar ‖ Corona`) is named
after a single-cause aurora event rather than a redundancy
construction: both lattice-family events that could trigger Aurora
share a common cause.

## What hash adds

Comet (FIPS 205 / SLH-DSA) rests on collision and preimage
resistance of the underlying hash function (SHA-2 or SHAKE
depending on parameter set), not on any lattice assumption. A
polynomial-time MLWE oracle does not yield a hash-collision oracle,
and vice-versa. This is the cross-family-disjointness property:

- A MLWE break compromises Pulsar AND Corona.
- A hash-family break compromises Comet AND every hash-anchored
  primitive in the stack (SHA-3, BLAKE3, Merkle trees, …) — but
  Pulsar and Corona survive.

Either failure leaves *at least one* of the three primitives
standing. That is the Magnetar safety property.

## Open question: third lattice family or true threshold-Comet?

The current Comet integration is GPU batch verify of *single-party*
SLH-DSA, not a threshold scheme. The Magnetar profile gates on a
batch of per-validator SLH-DSA signatures, not on a single
threshold-SLH-DSA cert. This is acceptable for cross-family DiD —
the per-validator sigs are individually unforgeable under
hash-family hardness — but the throughput is bounded by
N · (single-party SLH-DSA verify).

Two paths to a true threshold third leg:

1. **Threshold SLH-DSA**: research-track (Goyal–Kothapalli–Masny–
   Mukherjee IACR 2024/447). Would give Magnetar a single-cert
   third leg instead of N batched per-validator sigs. Substantial
   re-engineering.

2. **Code-family threshold** (HQC-side): NIST PQC4 selected HQC as
   the backup KEM. Mirror it on the signature side via a code-
   family threshold scheme. Even more research-track — Classic
   McEliece and HQC are KEMs, not signature schemes; code-based
   signature schemes (CFS, SDP-based) are not yet NIST-tier.

For now: Comet single-party batch verify is the third leg. The
Magnetar safety property holds: any single-family break leaves at
least one of Pulsar / Corona / Comet standing.

## Wire impact

```
Profile     Construction                       Per-block on-the-wire
─────────   ─────────────────────────────────  ─────────────────────
Pulsar      Module-LWE threshold (floor)         ~3.3 KB
Aurora      Pulsar ‖ Corona                      ~36 KB
Magnetar    Pulsar ‖ Corona ‖ Comet              ~36 KB + N × 35.7 KB
                                                  (N = signing committee)
```

Magnetar is heavy because the third leg is N per-validator SLH-DSA
signatures batched at verify time. When threshold-Comet ships, the
profile collapses to ~72 KB constant.

## See also

- [LP-0120](../../lps/LPs/lp-0120-quasar-mainnet-defaults.md) Quasar
  mainnet defaults and the strict-PQ profile gate.
- [README.md](README.md) — comparative index.
