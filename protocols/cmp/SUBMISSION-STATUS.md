# SUBMISSION-STATUS — CGGMP21 (Lux Profile)

> Honest framing. **Tier B** — production implementation, Lux-profile
> submission documentation in progress, formal submission gated per
> §3 below.

## §1 Tier classification

| Tier | Meaning | Status |
|---|---|---|
| A | Cut-ready submission package: spec consolidated, KAT manifest enforced, interop suites green, cut script verified | not yet |
| **B** | **Implementation production-grade; submission-shape docs being assembled; gaps explicit; not deadline-bound** | **current** |
| C | Implementation only; no submission scaffold | past state |

Cross-suite comparison:
- `luxfi/pulsar` — Tier A
- `luxfi/corona` — Tier B
- `protocols/cmp` (this) — Tier B
- `protocols/frost` — Tier B
- `protocols/bls` — Tier B

## §2 Submission tracks

CGGMP21 is not a NIST MPTC primary candidate (NIST has not
standardized threshold-ECDSA). The Lux profile targets:

| Track | Form | Status |
|---|---|---|
| Lux-profile precompile spec | LP-4720 | **Final** |
| Lux-profile precompile package (this dir) | 7 docs (README/SPEC/SUBMISSION-STATUS/PROOF-CLAIMS/PARAMS/TEST-VECTORS/SECURITY) | **Tier B in progress** |
| Academic/IETF formal submission | NIST has no MPTC track for threshold-ECDSA; possible CFRG draft authorship is roadmap | not pursued |
| ACVP / CAVP for the underlying ECDSA | Tracks `luxfi/crypto/secp256k1` upstream — not separately validated here | n/a |

The Lux production target is a Tier A submission tarball under
`scripts/cut-submission.sh` bundling SPEC + ref impl + KAT + interop.

## §3 Tier B → Tier A gating items

### 3.1 KAT determinism

- **Status**: KAT generator exists in tests; no Lux-specific KAT
  manifest yet.
- **Gate**: stand up `cmd/cmp_oracle/` (mirroring
  `corona/cmd/corona_oracle_v2/`); add `regen-kats.sh --verify`
  invariant.
- **Estimate**: 2-3 weeks.

### 3.2 Cross-validation against single-party ECDSA

- **Status**: tests cover Lux implementation; cross-validation
  against `crypto/ecdsa` (Go stdlib) + Bitcoin Core ECDSA verifier
  + Ethereum `geth` ECDSA verifier is partial.
- **Gate**: explicit cross-validation test exercising every
  signature against ≥3 third-party secp256k1 ECDSA verifiers.
- **Estimate**: 1-2 weeks.

### 3.3 Paillier-modulus generation audit

- **Status**: `pkg/paillier` exists; biprime testing per CCS '21
  Appendix C is implemented.
- **Gate**: published audit of Paillier-modulus generation against
  CCS '21 §6.1 mandates (specifically: prime-quality, blum-prime
  property, biprime soundness).
- **Estimate**: 1 week internal review + lab engagement for
  external.

### 3.4 Single-doc spec

- **Status**: SPEC.md + LP-4720 + CCS '21 paper.
- **Gate**: single `spec/cmp-lux.tex` consolidating these for
  reviewer convenience.
- **Estimate**: weeks.

### 3.5 Performance worksheet

- **Status**: benchmark tests exist (`cmp_benchmark_test.go`); no
  formal performance memo.
- **Gate**: measured-vs-paper table (per-round latency, CPU cost,
  Paillier-op count) with reproducibility script.
- **Estimate**: 1-2 weeks.

### 3.6 Identifiable-abort attribution

- **Status**: round-N share verification implemented; explicit Lux
  blame-attribution flow on partition/equivocation is undocumented.
- **Gate**: explicit `IDENTIFIABLE-ABORT.md` (or section in SPEC.md)
  with the Lux profile's blame rules.
- **Estimate**: 1 week.

### 3.7 Formal-methods overlay (research target)

- **Status**: no EasyCrypt theory, no Lean bridge, no Jasmin sources.
  Consistent with Corona's honest disclosure.
- **Gate**: EC theory shell for the Lux profile.
- **Estimate**: 8-16 weeks research + 12-16 weeks engineering.
  CGGMP21's UC framework + complex ZK subprotocols make this the
  most labor-intensive of the threshold primitives.

### 3.8 Independent cryptographic review

- **Status**: no formal sign-off doc.
- **Gate**: independent reviewer attests Lux profile correctness +
  CCS '21 conformance + Paillier handling + ZK subprotocol
  correctness.
- **Estimate**: depends on reviewer engagement; multi-month.

## §4 Non-promises

Per the project's "no AI slop / no fake closure" rule, this package
will NOT claim:

- Mechanized refinement until §3.7 closes
- Cryptographer sign-off until §3.8 closes
- NIST MPTC Class N1 byte-equality framing — NIST has not
  standardized threshold-ECDSA; the analogous claim here is
  "byte-identical to single-party secp256k1 ECDSA" which IS made
  in SPEC.md §2.2.

## §5 Cross-references

- Companion docs in this directory
- LP-4720 / LP-4730 / LP-4700
- `corona/SUBMISSION-STATUS.md` — Tier B template (this file mirrors)
- `pulsar/SUBMISSION.md` — Tier A reference target
