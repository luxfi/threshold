# Pulsar — Module-LWE validator authentication for Quasar

Pulsar is Lux's ML-DSA validator-authentication family. **It is not a
single infinite-threshold ML-DSA key.** It splits into two distinct
constructions that should never be conflated:

| Use | Construction | Where |
|---|---|---|
| **PulsarCert** — public leaderless consensus | **Unlimited-signer, stake-threshold ML-DSA certificate**. Each validator owns its own FIPS 204 ML-DSA key and signs independently. Quasar accepts the cert when the verified signer set crosses the configured stake/quorum threshold. | Lux Quasar consensus (P-Chain, finality envelopes) |
| **Threshold Pulsar** — custody / governance / bridge | 2-round t-of-n threshold construction. Per-party aggregated signature is **byte-identical** to single-party FIPS 204 ML-DSA-65 on the same `(pk, m)`. | `~/work/lux/pulsar/`, `~/work/lux/pulsar-mptc/` (NIST MPTC submission) |

These are *different cryptographic objects with different invariants*.
The first is a quorum predicate over many independent ML-DSA
signatures (no single threshold-produced ML-DSA σ); the second is a
single FIPS 204 σ produced by a multi-party ceremony. Both ship in
the Lux stack, in different lanes.

## PulsarCert — public consensus

PulsarCert is the cert form Quasar uses:

```
PulsarCert {
  message m
  validator_set_id
  signer indices / bitmap
  signatures σ_i
  signed_weight
}

valid iff
  ∀ i ∈ signers:  MLDSA.Verify(pk_i, m, σ_i) = true
  ∧ signed_weight ≥ quorum_threshold
```

The "threshold" lives in the **certificate predicate**, not inside any
single signature. A PulsarCert can omit signatures (e.g. by sampling
a deterministic committee, by Avalanche-style sampling, by checkpoint
frequency reduction, or by sidecar aggregate commitments) and remain
valid as long as the included signer set's weight crosses the
threshold. The verifier never sees a "threshold ML-DSA signature" —
it sees ordinary FIPS 204 σ's and a quorum bitmap.

This gives Lux **unlimited-signer semantics**: the global validator
set can grow without changing the verifier model, while each block /
checkpoint / epoch certificate stays bounded by policy.

## Threshold Pulsar — custody track

The NIST MPTC submission (`~/work/lux/pulsar-mptc/`) is the **second**
construction: a 2-round t-of-n threshold scheme whose aggregated
output is bit-identical to single-party FIPS 204 ML-DSA-65. This is
the right tool for:

- **Bridge custody** keys (B-Chain MPC).
- **Governance** keys with rotating committees.
- Any role where a single ML-DSA σ must be produced collaboratively
  without revealing the underlying secret to any single party.

Threshold Pulsar's per-party output is NOT a valid ML-DSA σ on its
own. The Combine step aggregates them into the single FIPS 204 σ.

## Construction (Threshold Pulsar, NIST MPTC track)

Per spec `pulsar-mptc/spec/pulsar.tex` Algorithm sign-r1 / sign-r2 /
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
