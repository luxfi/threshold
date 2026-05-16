# Pulsar — threshold Module-LWE / FIPS 204 byte-equal

Pulsar is the production-floor PQ-threshold scheme in the Lux Quasar
consensus stack. 2-round, t-of-n, output byte-identical to single-
party FIPS 204 ML-DSA-65.

## Construction (one paragraph)

Per spec `pulsar-mptc/spec/pulsar-m.tex` Algorithm sign-r1 / sign-r2 /
sign-agg: each party samples a fresh mask `y_i ← U_{γ_1}^ℓ` and
commits `D_i = cSHAKE(pack_w1(w_i), τ_1)` with sender-MACs. After
collecting peer commits + recovering aggregated `w̄ = HighBits(Σ w_j,
2γ_2)`, party `i` derives the FIPS 204 challenge `c̃ = SHAKE(μ ‖ w̄)`,
expands `c = SampleInBall(c̃)`, computes its Lagrange coefficient
`λ_i^T ∈ Z_q` for the quorum `T`, and emits `z_i = y_i + c·λ_i·s_i`
plus the polyvecl `r_i = c·λ_i·u_i` (the per-party contribution to
the aggregator's hint). The aggregator sums `z = Σ z_j`, `c·s_2 = Σ
r_j`, computes the hint `h`, evaluates the FIPS 204 rejection
predicates R1..R4 unconditionally, and on accept packs `σ = (c̃, z,
h)` — byte-identical to standard single-party FIPS 204 ML-DSA-65.

## Key claims

| Claim | Status |
|---|---|
| Class N1 byte-equal output to FIPS 204 | Algebraic argument: `pulsar-mptc/spec/pulsar-m.tex` Thm `thm:sign-correct`; Lean structural: `proofs/lean/Crypto/Pulsar/OutputInterchange.lean` |
| Class N4 reshare public-key preservation | `pulsar-mptc/spec/pulsar-m.tex` §4.5; Lean: `proofs/lean/Crypto/Pulsar/Shamir.lean` + `Crypto/Threshold_Lagrange.lean` |
| Unforgeability (EUF-CMA under static corruption) | `proofs/pulsar/unforgeability.tex` Thm `thm:pulsar-tsuf`; Lean: `proofs/lean/Crypto/Pulsar/Unforgeability.lean` |
| Constant-time | Harness present (`pulsar-mptc/ct/dudect/`); measurement TBD |
| Quantum resistance | Module-LWE + Module-SIS; NIST FIPS 204 standardized |

## Artifacts

| Where | What |
|---|---|
| `~/work/lux/pulsar/` | Library (production Go implementation) |
| `~/work/lux/pulsar-mptc/` | NIST MPTC submission package |
| `~/work/lux/pulsar-mptc/spec/pulsar-m.tex` | Specification (28 pages, NIST submission draft) |
| `~/work/lux/pulsar-mptc/ref/go/pkg/pulsar/` | Reference Go (89.7% test coverage, KAT-regen) |
| `~/work/lux/pulsar-mptc/jasmin/threshold/` | Jasmin high-assurance sources (round1 + round2 + combine implemented) |
| `~/work/lux/pulsar-mptc/proofs/easycrypt/Pulsar_N1.ec` | EasyCrypt N1 reduction (theory shell; core admit) |
| `~/work/lux/proofs/lean/Crypto/Pulsar/` | Lean structural proofs (zero `sorry`) |
| `~/work/lux/proofs/pulsar/*.tex` | Paper-level proof artifacts |
| `~/work/lux/papers/lp-073-pulsar/` | LP-073 specification paper |
| `~/work/lux/threshold/protocols/corona/` (sic) | The Lux internal threshold-protocol library currently houses the Pulsar-style ring-protocol under the `corona/` directory name. The naming here predates the Pulsar / Corona / Comet rename; the Module-LWE protocol skeleton lives there. |

## Open items (from BLOCKERS.md submission-status table)

- Spec ↔ Go-reference protocol drift: spec + Jasmin implement
  Lagrange-linearity FSwA; the Go ref currently uses a reveal-and-
  aggregate v0.1 trust model. Pick one before submission tag.
- EasyCrypt N1 6-step reduction core remains `admit` (research-track,
  needs EC expert + libjade `MLDSA65_Functional`).
- `jasminc` CI gate not exercised locally; sources are
  hand-reviewed against the libjade reference primitive set.
- Adaptive-corruption EUF-CMA: deferred to v0.2 (Game ADAPT in
  `proofs/pulsar/unforgeability.tex`).

## See also

- [README.md](README.md) — comparative index for the 3 PQ threshold tiers.
- [corona.md](corona.md) — Ring-LWE sibling.
- [comet.md](comet.md) — hash-based tier (structurally different).
