# Threshold ML-DSA

> **Status — research preview, NOT production.**
>
> | Lane | What's here | Status |
> |---|---|---|
> | **Per-validator ML-DSA** | N independent FIPS 204 signatures, aggregated at the consensus layer as `MLDSACertSet` | **Production.** Lives at [`luxfi/crypto/mldsa`](https://github.com/luxfi/crypto/tree/main/mldsa) (CIRCL-backed) + [`luxfi/warp` `MLDSACertSet`](https://github.com/luxfi/warp). This is the PQ identity-proof lane used by Warp 2.0 + bridge admin/pause schemes today. |
> | **Threshold ML-DSA** (this package) | RSS partitions, parameter tables, structural cert-set fuzz seed | **Research preview.** `keygen.go` / `sign.go` / `combine.go` / `a_posteriori.go` do **not** ship yet. `hrej.go::HRej` returns `"not yet wired to CIRCL ring"`. Do NOT depend on this package for live signing — there is no working signer to depend on. |
>
> The pattern mirrors `luxfi/magnetar` (FIPS 205 SLH-DSA): per-validator
> standalone primitive is production; true threshold without trusted
> dealer is research-grade and not yet deployed. The vocabulary
> distinction matters — see `magnetar/README.md` § "Why per-validator
> instead of threshold?" for the architectural reasoning.

---

First practical threshold signature scheme fully compatible with
**NIST FIPS 204 ML-DSA**. Outputs standard ML-DSA signatures (drop-in
verification) — once the signer lands. The current tree is the
paper-port scaffold up to that point.

Paper: Celi, del Pino, Espitau, Niot, Prest — *Efficient Threshold ML-DSA*,
USENIX Security 2026. The full LaTeX source is being prepared at
`papers/threshold-mldsa.tex` and is not yet checked in (the `hrej.go`
reference to that path will become live when the paper lands).

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

## Files (current tree)

| File | Status | Role |
|---|---|---|
| `doc.go` | ✅ shipped | package doc |
| `params.go` | ✅ shipped | (T,N) × level parameter sets (Tables 3, 10, 11) |
| `rss.go` | ✅ shipped | replicated secret sharing, hardcoded optimal partitions (Appendix B, Algorithm 6) |
| `hrej.go` | ⚠ stub | `HRej()` returns `"not yet wired to CIRCL ring"` |
| `rss_test.go` | ✅ shipped | RSS partition correctness + subset count + recovery |
| `fuzz_certset_test.go` | ✅ shipped | wire-format parser fuzz seed |
| `keygen.go` | ❌ not written | Algorithm 1 — paper port pending CIRCL ring integration |
| `sign.go` | ❌ not written | Algorithms 2–4 (commit / reveal / respond) |
| `combine.go` | ❌ not written | aggregate `z` + emit FIPS-204-byte-compat sig |
| `a_posteriori.go` | ❌ not written | Section 6.2 acceptance check + retry |

## Gap to "solid and done"

This list is mirrored in the parent `threshold/CLAUDE.md`.

**1-day fixes** (mostly docs / wiring):
1. Land `papers/threshold-mldsa.tex` or remove the citation from `hrej.go`.
2. NIST CAVP `.rsp` KAT vector ingestion in `luxfi/crypto/mldsa` (generator C exists at `c/ref/nistkat/PQCgenKAT_sign.c`; the Go side never consumes published vectors).
3. `FIPS-TRACEABILITY.md` in `luxfi/crypto/mldsa` mapping parameter sets → FIPS 204 sections.
4. Profile-level scheme pin in `luxfi/bridge/cmd/bridge/` so the daemon refuses an inbound non-PQ signing request when the operator profile names `ml-dsa-65`.

**Multi-week** (real research / engineering):
1. Implement `keygen.go` / `sign.go` / `combine.go` / `a_posteriori.go`. Paper claims 3-round protocol; none of the round transitions are coded.
2. End-to-end round-protocol test (2-of-3 keygen → sign → verify-via-CIRCL byte-compat). Without it the "byte-compatible with FIPS 204" claim in `doc.go` is unverified.
3. `dudect` constant-time validation on the per-party sign path once it exists.
4. External cryptographer sign-off (Tier A submission shape, mirroring `magnetar/CRYPTOGRAPHER-SIGN-OFF.md`).
5. Benchmark harness (`mldsa_bench_test.go.broken` already exists in `crypto/mldsa` as a broken artifact — repair + add a threshold bench).
