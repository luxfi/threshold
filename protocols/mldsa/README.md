# Threshold ML-DSA

First practical threshold signature scheme fully compatible with
**NIST FIPS 204 ML-DSA**. Outputs standard ML-DSA signatures (drop-in
verification).

Paper: Celi, del Pino, Espitau, Niot, Prest — *Efficient Threshold ML-DSA*,
USENIX Security 2026. See [`../../papers/threshold-mldsa.tex`](../../papers/threshold-mldsa.tex).

## Configurations

- Security levels: **ML-DSA-44 / 65 / 87** (NIST I / III / V)
- Threshold range: `2 ≤ T ≤ N ≤ 6` (hard upper bound in this release)
- Typical: `2-of-3`, `3-of-5`
- Security model: **static dishonest majority** in the ROM

## Rounds

3 rounds per signing attempt, `K` parallel instances (see `params.go`):

1. Commit — each party publishes `H(vk, i, wᵢ)` with `wᵢ = A·rᵢ`
2. Reveal — open `wᵢ`, derive challenge `c`
3. Respond — each party publishes `zᵢ` after local hyperball rejection

Combiner verifies the aggregated `z` meets ML-DSA bounds and emits a
standard signature.

## Bandwidth (per party, per successful attempt, ML-DSA-44)

| N\T | 2 | 3 | 4 | 5 | 6 |
|-----|----|----|----|----|----|
| 2 | 10.5 kB | | | | |
| 3 | 15.8 kB | 21.0 kB | | | |
| 4 | 15.8 kB | 36.8 kB | 42.0 kB | | |
| 5 | 15.8 kB | 73.5 kB | 157.4 kB | 84.0 kB | |
| 6 | 21.0 kB | 99.8 kB | 388.4 kB | 524.8 kB | 194.2 kB |

## Files

- `doc.go` — package doc
- `params.go` — all (T,N) × level parameter sets (Tables 3, 10, 11)
- `rss.go` — replicated secret sharing, hardcoded optimal partitions (Appendix B, Algorithm 6)
- `hrej.go` — imbalanced hyperball rejection (Figure 4)
- _TODO_: `keygen.go`, `sign.go`, `combine.go`, `a_posteriori.go`
  — stubs pending integration with `cloudflare/circl/sign/mldsa` and `luxfi/lattice`.

## Status

Skeleton + parameter tables + RSS partition logic shipped.
Ring operations, CIRCL integration, and full protocol wiring land incrementally.
