# SUBMISSION-STATUS — FROST (Lux Profile)

> Honest framing. **Tier B** — production implementation, Lux-profile
> submission documentation in progress, formal IETF / NIST submission
> gated per §3 below.

## §1 Tier classification

| Tier | Meaning | Status |
|---|---|---|
| A | Cut-ready submission package: spec consolidated, KAT manifest enforced, interop suites green, cut script verified | not yet |
| **B** | **Implementation production-grade; submission-shape docs being assembled; gaps explicit; not deadline-bound** | **current** |
| C | Implementation only; no submission scaffold | past state |

Cross-suite comparison:
- `luxfi/pulsar` — Tier A (full submission package, mechanized refinement vs FIPS 204)
- `luxfi/corona` — Tier B (honest no-mechanized-proof disclosure)
- `protocols/frost` (this) — Tier B (Lux profile of upstream CFRG draft)
- `protocols/cmp` — Tier B
- `protocols/bls` — Tier B

## §2 Submission tracks

FROST is not a NIST MPTC primary candidate (it is upstream IETF/CFRG
work). The Lux profile targets two submission tracks:

| Track | Form | Status |
|---|---|---|
| IETF CFRG profile update | Contributing to / mirroring `draft-irtf-cfrg-frost-15` (or current) | Lux profile codified in LP-4711/LP-4712; pull-request to CFRG is roadmap |
| Lux-profile precompile spec | LP-4710 (precompile spec) + LP-4711/4712 (ciphersuites) | **Final** |
| NIST MPTC analogue (Class N1) | Not applicable — FROST has no NIST standard verifier; cross-validation is against the CFRG draft | n/a |

The Lux production target is a **Tier A submission tarball** under
`scripts/cut-submission.sh` that bundles SPEC + ref impl + KAT + interop.

## §3 Tier B → Tier A gating items

In rough priority order. Each is real engineering / formal-methods
work, not paperwork.

### 3.1 KAT determinism

- **Status**: KAT generator exists in tests (`frost_*_test.go`);
  Lux-specific KAT manifest under
  `scripts/regen-kats.manifest.sha256`-style enforcement does NOT
  exist for FROST yet.
- **Gate**: stand up `cmd/frost_oracle/` (mirroring
  `corona/cmd/corona_oracle_v2/`) that produces deterministic KATs
  per ciphersuite; add `regen-kats.sh --verify` invariant.
- **Estimate**: 1-2 weeks.

### 3.2 Upstream CFRG cross-validation

- **Status**: tests cover Lux's own implementation; no published
  third-party verifier exists for round-2 share verification
  outside of the protocol itself.
- **Gate**: differential testing against the reference
  implementations linked from the CFRG draft (typically
  `cfrg/draft-irtf-cfrg-frost`'s test fixtures).
- **Estimate**: 1 week.

### 3.3 Integration spec consolidation

- **Status**: SPEC.md + LP-4710/4711/4712 + upstream CFRG draft.
- **Gate**: single `spec/frost-lux.tex` consolidating these (mirror
  Pulsar's `spec/pulsar.tex` shape) for reviewer convenience.
- **Estimate**: weeks.

### 3.4 Identifiable-abort attribution

- **Status**: round-2 shares are individually verifiable, but the
  Lux-profile blame-attribution flow on partition / equivocation
  is not formally specified beyond the upstream construction.
- **Gate**: explicit `IDENTIFIABLE-ABORT.md` (or section in SPEC.md)
  with the Lux profile's attribution rules.
- **Estimate**: 1 week.

### 3.5 Formal-methods overlay (Tier B → A research target)

- **Status**: no EasyCrypt theory, no Lean bridge, no Jasmin sources
  for the threshold layer (consistent with Corona's honest
  disclosure).
- **Gate**: EC theory shell for the Lux profile, multi-month.
- **Estimate**: 6-12 weeks research + 8-12 weeks engineering.

### 3.6 Independent cryptographic review

- **Status**: no formal sign-off doc (cf. Pulsar's
  CRYPTOGRAPHER-SIGN-OFF.md).
- **Gate**: independent reviewer attests Lux profile correctness +
  CFRG-draft conformance + integration soundness.
- **Estimate**: depends on reviewer engagement.

## §4 Non-promises

Per the project's "no AI slop / no fake closure language" rule, this
package will NOT claim:

- Mechanized refinement until §3.5 closes
- Cryptographer sign-off until §3.6 closes
- IETF-draft authorship status (Lux is a downstream profile, not the
  draft author) until / unless a CFRG submission lands
- NIST MPTC Class N1 byte-equality — N1 framing applies to schemes
  with a NIST standard verifier; FROST does not have one

## §5 Cross-references

- `README.md`, `SPEC.md`, `PROOF-CLAIMS.md`, `PARAMS.md`,
  `TEST-VECTORS.md`, `SECURITY.md` — companion docs
- LP-4710 / LP-4711 / LP-4712 / LP-4700
- `corona/SUBMISSION-STATUS.md` — Tier B template (this file mirrors)
- `pulsar/SUBMISSION.md` — Tier A reference target
