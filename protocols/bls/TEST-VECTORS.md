# TEST-VECTORS — Threshold BLS (Lux profile)

> KAT format specification + upstream-vector cross-references for
> the threshold-BLS package at
> `github.com/luxfi/threshold/protocols/bls`.

## §1 Status

| Aspect | Status |
|---|---|
| KAT generator (`cmd/bls_oracle/`) | NOT PRESENT — Tier-A gate (see `SUBMISSION-STATUS.md` §3.2) |
| Cross-runtime byte-equality CI gate | NOT PRESENT |
| Unit-test KATs | Embedded in `bls_test.go` (small fixtures, not externally-published) |
| Upstream single-party BLS KATs | Reused via `luxfi/crypto/bls` test suite |

This document specifies what the KAT format **will look like** when
the generator lands, and pins the upstream-vector sources for the
underlying BLS primitive.

## §2 Upstream BLS vectors (single-party — REUSED)

The threshold-BLS aggregated output, by §5.1 of `SPEC.md`, is
**byte-equal** to a single-party BLS signature under the same
master secret. Therefore the existing single-party BLS test
vectors are valid threshold-BLS aggregated-output vectors.

### §2.1 IETF draft KATs

Source: `draft-irtf-cfrg-bls-signature-05` Appendix A.

These are the canonical hash-to-curve and signing KATs for the
ciphersuite `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_`. They cover:

- Hash-to-curve outputs for a sequence of fixed inputs.
- Sign / Verify / Aggregate / FastAggregateVerify pairs.

**Cross-validation**: `luxfi/crypto/bls`'s test suite consumes these
vectors. Any threshold-BLS aggregate that fails to byte-match a
single-party BLS signature on the same master + message will
manifest as a failure when the same `(PK, m, σ)` is run through
`bls.Verify`.

### §2.2 IRTF CFRG test-vector repository

Source: <https://github.com/cfrg/draft-irtf-cfrg-bls-signature>
(`vectors/` subdirectory of the IETF CFRG BLS draft repository).

Provides JSON-formatted test vectors covering edge cases
(infinity-point handling, subgroup-check failures, malformed
encodings). Suitable for the eventual `cmd/bls_oracle/` cross-
runtime manifest.

## §3 Threshold-specific vector format (PROPOSED — not yet generated)

The threshold layer needs vectors that **also** exercise the
share-distribution and combine path, not just the verifier.

### §3.1 Vector schema

```json
{
  "name": "threshold_bls_3of5_msg1",
  "ciphersuite": "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_",
  "curve": "BLS12-381",
  "threshold": 3,
  "totalParties": 5,
  "parties": ["alice", "bob", "carol", "dave", "eve"],
  "masterSecret": "...32 bytes hex (test only; never exposed in production)...",
  "groupPK": "...48 bytes hex (G1 compressed)...",
  "shares": {
    "alice":  "...32 bytes hex (s_alice)...",
    "bob":    "...32 bytes hex (s_bob)...",
    ...
  },
  "verificationShares": {
    "alice":  "...48 bytes hex (g_1^s_alice)...",
    ...
  },
  "message": "...hex...",
  "activeQuorum": ["alice", "bob", "carol"],
  "partialSignatures": {
    "alice":  "...96 bytes hex (G2 compressed)...",
    "bob":    "...96 bytes hex...",
    "carol":  "...96 bytes hex..."
  },
  "aggregatedSignature": "...96 bytes hex (G2 compressed)...",
  "singlePartyComparator": "...96 bytes hex (bls.Sign(masterSecret, m))..."
}
```

The load-bearing assertion is:
```
aggregatedSignature == singlePartyComparator   (byte-for-byte equal)
```

### §3.2 Coverage matrix (target)

| Threshold | Total parties | Active quorum size | Notes |
|---|---|---|---|
| 2 | 3 | exactly 2 | Smallest non-trivial case |
| 3 | 5 | exactly 3 | Typical custody profile |
| 3 | 5 | 4 (1 extra share) | Asserts the `shares = shares[:threshold]` truncation behaviour matches single-party |
| 5 | 9 | exactly 5 | Mid-size committee |
| 7 | 11 | exactly 7 | Larger committee |
| 10 | 15 | exactly 10 | Stress profile |

Each row should be deterministic from a fixed seed; CI should
regenerate and assert byte-equality with the checked-in JSON.

### §3.3 Negative vectors

| Case | Expected outcome |
|---|---|
| Quorum below `t` | `AggregateSignatures` returns `insufficient signatures` error |
| Malformed partial signature byte string | `AggregateSignatures` returns `invalid signature from party ...` error |
| Party-ID maps to scalar 0 (CONSTRUCTED CASE) | Documented in `SPEC.md` §4.2 as a must-not; should fail validation once §3.7 of `PROOF-CLAIMS.md` lands. Currently NOT validated. |
| Wrong message in one partial signature | Per-share verification rejects it; combine proceeds incorrectly without per-share verification |

## §4 KAT-deterministic generation (PROPOSED)

When `cmd/bls_oracle/` lands it should:

1. Take a seed `s` from `--seed` (default `0x00…00`).
2. Derive `masterSecret = HKDF-Expand(s, "Lux-threshold-BLS-master")`.
3. Construct `f` of degree `t − 1` with `f(0) = masterSecret` and
   higher coefficients via HKDF chain.
4. Emit the JSON vector above.
5. Cross-run against the C++ port at
   `~/work/luxcpp/crypto/bls/threshold/` (when that exists) and
   assert byte-identical KAT manifest.

This mirrors the Corona pattern: `cmd/{reshare,dkg2,activation,
cross_runtime,sign}_oracle/` plus `scripts/regen-kats.sh --verify`.

## §5 Where the unit-test fixtures live today

See `bls_test.go`:

- `TestThresholdBLS_2of3` — exercises the 2-of-3 happy path.
- Additional 3-of-5 and quorum-edge cases are present in the file.

These fixtures are **not** externalised as JSON KATs. They use
random keygen per test (no deterministic seed), so they validate
algebraic correctness (every aggregate verifies under the group PK)
but do NOT validate byte-equality across runtimes.

Externalising them is the Tier-A gate in `SUBMISSION-STATUS.md`
§3.2.

## §6 References

- IETF `draft-irtf-cfrg-bls-signature-05` Appendix A — single-party
  BLS KATs.
- IRTF CFRG BLS test-vector repository.
- `luxfi/crypto/bls` test suite — already consumes the upstream
  vectors.
- Boldyreva 2003 — threshold-BLS construction (no vectors in the
  paper itself; the construction's correctness statement implies
  byte-equality with single-party BLS under the master secret).
- `protocols/corona` `cmd/cross_runtime_oracle/` — reference design
  for the eventual `cmd/bls_oracle/`.

---

**Document metadata**

- Name: `TEST-VECTORS.md`
- Version: v0.1 (initial submission-package scaffolding)
- Date: 2026-05-18
- KAT generator status: NOT IMPLEMENTED (Tier-A gate)
