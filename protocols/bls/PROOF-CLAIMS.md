# PROOF-CLAIMS — Threshold BLS (Lux profile) — HONEST framing

> **What this Tier B package proves, and — critically — what it does NOT.**
> Read this before reading the threshold-BLS code. The framing matters
> as much as the implementation.

## §1 The narrow claim this package makes

The strongest precise statement supported by the current `bls.go`:

> **Construction-level output interchangeability.** Every signature
> byte string produced by `AggregateSignatures(shares, t)` on inputs
> `(group_pk, m, shares)` — where `shares` are exactly `t` honest
> partial signatures over the same message `m` under the
> verification-share assignment from a single `TrustedDealer.
> GenerateShares` run — is byte-equal to the single-party
> `bls.Sign(s_master, m)` signature under `luxfi/crypto/bls`, where
> `s_master = f(0)` is the master secret used by the dealer.

**Formal-statement status**: stated in prose, validated by
inspection + `bls_test.go`, inherited from Boldyreva 2003 §3 (gap-
Diffie-Hellman threshold construction) and the standard Shamir-
Lagrange identity over a finite field. **NOT mechanized** in
EasyCrypt, Lean, Jasmin, or any other proof assistant at this
revision. See §3 below.

## §2 What IS provided

| Aspect | Status | Source |
|---|---|---|
| Implementation matches Boldyreva 2003 §3 | ✓ by code review | `bls.go` |
| Implementation matches Shamir-Lagrange algebra over `F_r` | ✓ by code review | `bls.go:65 AggregateSignatures` + `pkg/math/polynomial` |
| Aggregated output byte-verifies under `luxfi/crypto/bls.Verify` | ✓ by unit test | `bls_test.go` |
| Per-share verification (`g_1^{s_i}` consistent with `σ_i = H(m)^{s_i}`) | ✓ by implementation | `Config.VerifyPartialSignature` |
| Trusted-dealer keygen sound (master secret == `f(0)` matches `groupPK == g_1^{f(0)}`) | ✓ by implementation | `TrustedDealer.GenerateShares` |
| Compatibility with `luxfi/crypto/bls` single-party verifier | ✓ by inspection (same signature group, same encoding) | `bls.go:114-117` |

## §3 What is NOT proved (HONEST)

This section is the load-bearing honesty disclosure. Read it.

### §3.1 NOT proved: mechanized refinement

This package ships **no EasyCrypt theories, no Lean theorems, no
Jasmin sources**.

**Why**: the threshold-BLS construction has no NIST standard target
to refine against. There is no FIPS standard for threshold BLS; the
underlying BLS itself is captured by IETF `draft-irtf-cfrg-bls-
signature-05` which has been a draft for years and is not yet a
NIST-validated primitive. Mechanizing the threshold layer against
an academic paper (Boldyreva 2003) is a multi-month research project
with no anchored target.

Compare to Pulsar (`luxfi/pulsar`), which can refine against
FIPS 204 — that's why Pulsar has 13/13 EasyCrypt files compiling
clean and this package has zero.

**What this means in practice**: the trust base for the threshold
combine reduces to:
- Boldyreva 2003 §3 academic analysis.
- Shamir 1979 + Lagrange interpolation textbook identity.
- The Go reference implementation code review against those.
- Unit-test cross-validation: every produced aggregate verifies
  under `luxfi/crypto/bls.Verify` (the same verifier any external
  consumer would use).

### §3.2 NOT proved: distributed key generation soundness

The current implementation uses a **trusted dealer**. The dealer
holds `f(0)` in memory for the duration of `GenerateShares` and
must be trusted not to leak it, not to construct a malicious `f`,
and not to publish inconsistent verification keys.

This is **stronger than the N4 trust assumption**. NIST MPTC N4
requires the multi-party key-generation step to be
adversary-tolerant. The current package does not satisfy N4.

A Pedersen-style DKG over `F_r` would close this gap. See
`SUBMISSION-STATUS.md` §3.1.

### §3.3 NOT proved: BLS hardness assumption

This package says nothing about `co-CDH` hardness over BLS12-381.
The defensible classical-security claim:

> Threshold-BLS in this package is secure against forgery under the
> `co-CDH` hardness assumption over BLS12-381 in the random-oracle
> model on the IETF `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_`
> hash-to-curve, exactly as the single-party BLS in
> `luxfi/crypto/bls` is.

**NOT defensible**:
> Threshold-BLS in this package is post-quantum secure.

(BLS is classically secure only. Shor's algorithm breaks pairing-
based crypto. PQ replacement is Pulsar (M-LWE) or Corona (R-LWE) at
the threshold layer.)

### §3.4 NOT proved: cross-runtime byte-equality enforced by CI

There is **no** KAT manifest at `scripts/regen-kats.sh` covering
threshold-BLS. Byte-equality across implementations (Go ↔ C++ port)
is asserted by inspection only, not by CI gating.

Compare to Corona, which has `scripts/regen-kats.sh --verify`
enforcing byte-identical KATs between Go and `~/work/luxcpp/
crypto/corona/`. The threshold-BLS path has no such enforcement.

This is `SUBMISSION-STATUS.md` §3.2.

### §3.5 NOT proved: constant-time at threshold layer

The single-party `luxfi/crypto/bls` inherits its CT story from
`cloudflare/circl`. The threshold layer adds:

- Lagrange-coefficient computation in `F_r`.
- Scalar-multiplication of G2 points by Lagrange coefficients.
- Per-share lookup keyed by `party.ID`.

None of these have been subjected to a per-path constant-time
audit at the threshold-protocol level. See
`SUBMISSION-STATUS.md` §3.6.

### §3.6 NOT proved: rogue-key resistance under DKG

Under the current trusted-dealer keygen, rogue-key attacks are
trivially blocked because the dealer controls all verification keys
and constructs them coherently from `f`. Under a future
publicly-verifiable DKG, rogue-key resistance requires either:

- Proof-of-possession (PoP) on each verification key share, OR
- A polynomial commitment that constrains every `VK_i = g_1^{f(i)}`
  to a single polynomial `f` chosen via a verifiable joint coin-
  toss.

Neither is implemented. Threshold-BLS without a DKG is rogue-key-
safe **by construction of the dealer**, not by adversary-tolerant
protocol design.

### §3.7 NOT proved: party-ID zero-guard

`SPEC.md` §4.2 documents that `party.ID(i).Scalar(BLS12381G1) == 0`
is a must-not. The implementation does **not** validate this on
`Config` construction or on `TrustedDealer.GenerateShares`. A
caller who passes a party ID whose UTF-8 byte sequence happens to
map to `0 mod r` will silently produce a share equal to the master
secret.

This is a low-probability but non-zero implementation bug; closing
it is a Tier-A gate.

### §3.8 NOT proved: protocol-level adversarial robustness

The implementation's correctness claim assumes:
- Honest quorum on the active signing path.
- Trusted dealer at keygen time.
- Synchronous network (no asynchronous-abort logic; aggregate just
  fails-closed if a malicious partial signature is mixed in
  without per-share verification).

No `identifiable abort` evidence pipeline exists at this layer
(compare CGGMP21 `protocols/cmp` which does identify a misbehaving
party). For threshold-BLS, per-share verification by the aggregator
is the only mitigation against a single malicious signer; localizing
the malicious party is a caller responsibility.

## §4 Refinement chain (what's connected to what)

```
Go implementation (bls.go)
       implements (by code review + unit test)
Boldyreva 2003 §3 threshold-BLS construction
  + Shamir-Lagrange algebra over F_r
  + Lux profile (party-ID encoding, polynomial convention)
       conforms to (by inspection against IETF draft + Lux LP-4110)
Single-party BLS in luxfi/crypto/bls
  (which itself is implemented on top of cloudflare/circl)
```

Every "implements" / "conforms" relation is by **inspection and
test**, NOT machine-checked.

## §5 What an auditor verifying this package should do

1. **Read** `README.md` for the lay of the land.
2. **Read** this document (`PROOF-CLAIMS.md`) for what's proved vs not.
3. **Read** `SUBMISSION-STATUS.md` §3 for the Tier-A gates.
4. **Read** Boldyreva 2003 for the academic construction.
5. **Read** IETF `draft-irtf-cfrg-bls-signature-05` for the BLS
   ciphersuite encoding.
6. **Run** `go test ./protocols/bls/...` — expect green.
7. **Read** `bls.go` line-by-line, cross-checking against §3 of
   `SPEC.md` (curve / ciphersuite) and §4 (sharing scheme).
8. **Run** a manual KAT cross-check: generate a threshold signature
   under a fixed master secret + party set, verify byte-equality
   against `luxfi/crypto/bls.Sign(master_secret, m)`. (CI enforcement
   is a Tier-A gate.)

## §6 The honest one-paragraph version

> This package establishes that the Go reference implementation
> faithfully implements Boldyreva's gap-DH threshold BLS construction
> over BLS12-381 with Shamir secret sharing and Lagrange combine.
> Aggregated signatures are byte-equal to single-party BLS signatures
> under the same master secret. The current implementation uses a
> trusted dealer at keygen time — no publicly-verifiable DKG — so it
> satisfies an N1 analogue (output-interchangeability) but does NOT
> satisfy NIST MPTC Class N4 (multi-party key generation). No
> mechanized refinement proof (EasyCrypt, Lean, Jasmin) is shipped;
> no NIST standard target exists for threshold BLS. No CI-enforced
> cross-runtime KAT manifest. No threshold-layer constant-time audit.
> No external cryptographic audit. The closure path to Tier A is
> enumerated in `SUBMISSION-STATUS.md` §3.

## §7 Roadmap (multi-version closure path)

| Milestone | Notes |
|---|---|
| Cross-runtime KAT manifest + `cmd/bls_oracle/` | Short-term — `SUBMISSION-STATUS.md` §3.2 |
| Party-ID zero-guard at `Config` construction | Short-term — §3.7 |
| Threshold-layer constant-time review | Short-term — §3.5 |
| LP slot allocation under 4700-4799 | Medium-term — `SUBMISSION-STATUS.md` §3.3 |
| Pedersen DKG over `F_r` (replaces trusted dealer) | Medium-term — §3.2 / N4 enablement |
| EasyCrypt theory or Lean bridge for Lagrange-aggregation | Long-term, multi-month |
| External audit (engaged lab) | Long-term |
| dudect-style statistical CT validation | Long-term |

The closure path is real but long. The honest framing at this
revision: production-hardened implementation of a published academic
construction with a trusted-dealer keygen, NOT machine-checked
refinement of a NIST standard, NOT N4-compliant.

---

**Document metadata**

- Name: `PROOF-CLAIMS.md`
- Version: v0.1 (initial submission-package scaffolding)
- Date: 2026-05-18
