# SUBMISSION-STATUS — Threshold BLS (Lux profile)

> **Honest framing.** This package is at **Tier B**: production
> implementation, NIST/IETF-submission-shaped documentation in
> progress, formal submission gated on the items enumerated below.

## §1 Tier classification

| Tier | Meaning | Status here |
|---|---|---|
| **A** | Cut-ready submission package: spec consolidated, KAT manifest enforced cross-runtime, formal proofs (or honest disclosure of their absence), interop suites green, cut script verified. Reviewer can run `scripts/cut-submission.sh` and obtain a self-contained tarball. | **Not yet** |
| **B** | Implementation production-grade; submission-shape docs being assembled; gaps explicitly enumerated. Not deadline-bound. | **Current** |
| C | Implementation only; no submission scaffold. | Past state. |

Compare to siblings:
- `luxfi/pulsar` — Tier A (full submission package, mechanized refinement against FIPS 204).
- `luxfi/corona` — Tier B (submission package, honest no-proof disclosure).
- `protocols/bls` (this) — Tier B (submission package, honest no-proof + no-DKG disclosure).
- `protocols/frost` — Tier B.
- `protocols/cmp` — Tier B.

## §2 What exists today

| Artifact | Status | Location |
|---|---|---|
| Go reference implementation | Production | `bls.go` |
| Unit tests | Pass (2-of-3, 3-of-5) | `bls_test.go` |
| Per-party verification | Implemented | `Config.VerifyPartialSignature` |
| Aggregate verification | Implemented | `Config.VerifyAggregateSignature` |
| Trusted-dealer keygen | Implemented | `TrustedDealer.GenerateShares` |
| JSON-RPC integration | Wired into `pkg/thresholdd/` `bls.{keygen,sign,verify}` | `pkg/thresholdd/server.go` |
| Submission cover sheet (this set) | This revision | `protocols/bls/{README,SPEC,SUBMISSION-STATUS,PROOF-CLAIMS,TEST-VECTORS,SECURITY,PARAMS}.md` |

## §3 What is NOT yet present (the Tier B → Tier A path)

### §3.1 Publicly-verifiable DKG

**Status**: NOT IMPLEMENTED. Current keygen uses a `TrustedDealer`
that holds the master secret in memory for the duration of share
distribution.

**Tier-A gate**: a Pedersen-DKG over `F_r` (BLS12-381 scalar field)
with hiding blinds, replacing the trusted dealer. Lifecycle should
mirror Corona's `dkg2/` (Pedersen DKG over `R_q`) — i.e., dealer-free
key generation with publicly-verifiable commitments.

**Why this matters for NIST framing**: NIST MPTC Class N4 requires
multi-party key generation. A trusted-dealer scheme does not satisfy
N4. Threshold BLS without DKG can claim N1-analogue
(output-interchangeability) but NOT N4.

### §3.2 Cross-runtime KAT manifest

**Status**: NOT WIRED. There is no `cmd/bls_oracle/` and no
`scripts/regen-kats.sh` invocation for the threshold-BLS path.

**Tier-A gate**: deterministic KAT generator + manifest enforced
against the corresponding C++ port at
`~/work/luxcpp/crypto/bls/threshold/` (when that exists).
Until then the threshold-BLS cross-runtime byte-equality invariant
is asserted by code review only, not by CI.

### §3.3 LP slot

**Status**: NO LP allocated.

The classical BLS12-381 precompiles are LP-3653 + LP-4110
(single-party + aggregate-signature). The threshold-MPC family
umbrella (LP-4700) does not yet allocate a slot for threshold BLS.

**Tier-A gate**: a child LP under 4700-4799 (likely LP-4730 or
similar, after the FROST 4710-4712 + CGGMP21 4720 slots) covering
the precompile interface, gas cost, encoding, and ciphersuite
binding.

### §3.4 Proof tier

**Status**: NO MECHANIZED REFINEMENT. See `PROOF-CLAIMS.md` §3.

**Tier-A gate (long path)**: at minimum, an EasyCrypt theory or
a Lean bridge for the Lagrange-aggregation algebraic identity over
`F_r` (analogous to Pulsar's `lagrange_inverse_eval` and
`reconstruct_linear` bridges). Multi-month research item.

### §3.5 Cut script + tarball reproducibility

**Status**: NOT PRESENT.

**Tier-A gate**: a `scripts/cut-submission.sh` analogue at the
`threshold/protocols/bls/` level (or a unified one at the
`threshold/` repo root that knows about this sub-package), regenerating
KATs and producing a self-contained tarball.

### §3.6 Constant-time audit

**Status**: NOT PERFORMED at threshold layer (single-party `luxfi/
crypto/bls` inherits its CT story from the cloudflare/circl
backend).

**Tier-A gate**: a `CONSTANT-TIME-REVIEW.md` analogous to Corona's,
specifically auditing the threshold-layer scalar operations
(Lagrange coefficient computation, scalar mul of G2 points by
those coefficients) for secret-dependent branching.

### §3.7 dudect-style statistical CT validation

**Status**: NOT PRESENT.

**Tier-A gate**: same as Corona §3.4 — a dudect harness for the
threshold combine path. Roadmap-level.

### §3.8 External cryptographic audit

**Status**: NOT ENGAGED.

**Tier-A gate**: third-party audit covering at minimum the
threshold combine, the partial-signature verification, and the
party-ID-to-scalar embedding (§4.2 of `SPEC.md` flags an unguarded
zero case).

## §4 Suggested closure ordering

The Tier B → Tier A path is realistically multi-quarter. A
defensible ordering:

1. **Now**: this submission-package scaffold (this commit).
2. **Short term (weeks)**: KAT generator + cross-runtime manifest +
   constant-time review + party-ID zero-guard.
3. **Medium term (months)**: LP slot allocation + Pedersen-DKG over
   `F_r` + dudect harness.
4. **Long term (quarters)**: EasyCrypt theory or Lean bridge for
   Lagrange-aggregation identity + external audit + cut script.

Each step is independently merge-able and value-additive; no step
requires the next step to be useful.

## §5 What this submission package DOES claim, today

> The Go reference implementation in `bls.go` faithfully implements
> Shamir-Lagrange threshold BLS over BLS12-381 per Boldyreva 2003,
> using `luxfi/crypto/bls` (built on `cloudflare/circl`) as the
> single-party BLS base primitive. Under the trusted-dealer keygen
> currently shipped, aggregated signatures from any honest `t`-of-`n`
> quorum are byte-equal to single-party BLS signatures on the
> reconstructed master secret, and verify under any standard BLS
> verifier.

That's the honest, defensible statement. Everything beyond it
(no-trusted-dealer, mechanized proof, cross-runtime KAT manifest)
is roadmap.

## §6 Compatibility with the unified threshold daemon

The `pkg/thresholdd/` JSON-RPC dispatcher exposes:

- `bls.keygen` → `TrustedDealer.GenerateShares`
- `bls.sign`   → `Config.Sign` (per party) + `AggregateSignatures`
- `bls.verify` → `bls.Verify` (single-party verifier, see §5.1)

This is the **only** caller path in production today; precompile
wiring is gated on §3.3.

---

**Document metadata**

- Name: `SUBMISSION-STATUS.md`
- Version: v0.1 (initial submission-package scaffolding)
- Date: 2026-05-18
- Tier label at this revision: **B**
