# PARAMS — Threshold BLS (Lux profile) — parameter-set worksheet

> Parameter choices for the threshold-BLS package at
> `github.com/luxfi/threshold/protocols/bls`.

## §1 Single parameter set in v0.x

This package ships **one** parameter set (BLS12-381 with the IETF
G2-signature ciphersuite). The reason there is exactly one set:

- The underlying single-party BLS in `luxfi/crypto/bls` ships
  exactly one ciphersuite.
- The threshold layer does not introduce any new field, group, or
  hash — it reuses the single-party primitive byte-for-byte.

A future second parameter set (e.g., G1-signature variant, or a
different pairing-friendly curve) would require an LP and a new
sub-package.

## §2 Cryptographic parameters

| Identifier | Value | Source |
|---|---|---|
| Curve | BLS12-381 | `cloudflare/circl/ecc/bls12381` |
| Public-key group `G_1` | 48-byte compressed | IETF `draft-irtf-cfrg-bls-signature-05` |
| Signature group `G_2` | 96-byte compressed | IETF `draft-irtf-cfrg-bls-signature-05` |
| Target group `G_T` | Pairing output, internal | circl pairing |
| Scalar field order `r` | `0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001` | BLS12-381 group order |
| Base-field characteristic `p` | `0x1a0111ea397fe69a4b1ba7b6434bae35`  ... (381 bits) | BLS12-381 base prime |
| Pairing embedding degree `k` | 12 | BLS12-381 |
| Hash-to-curve | `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_` | IETF draft §4.2.2 |
| Ciphersuite tag | `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_` | `luxfi/crypto/bls` Sign |
| Random-oracle hash | SHA-256 (per ciphersuite) | FIPS 180-4 |

### §2.1 Classical security level

| Property | Bits | Source |
|---|---|---|
| Discrete-log in `G_1` / `G_2` | ~128 | BLS12-381 standard analysis |
| `co-CDH` in `(G_1, G_2)` | ~128 | Inherits from DL hardness |

### §2.2 Post-quantum security level

| Property | Bits | Source |
|---|---|---|
| Any pairing-based assumption | 0 (BROKEN BY SHOR) | Standard PQ analysis |

BLS is **classically secure only**. PQ replacements are:
- Pulsar (`luxfi/pulsar`) — Module-LWE threshold, FIPS 204 byte-equal.
- Corona (`luxfi/corona`) — Ring-LWE threshold, construction-level.

## §3 Threshold parameters

| Identifier | Value | Constraint |
|---|---|---|
| Threshold `t` | `Config.Threshold` | `1 ≤ t ≤ n` |
| Total parties `n` | `Config.TotalParties` | `n ≥ t` |
| Sharing polynomial degree | `t − 1` | `bls.go:171` |
| Party-ID embedding | `party.ID(i).Scalar(F_r)` | Must be non-zero (§4.1) |

### §3.1 Supported `(t, n)` ranges

The implementation imposes **no** hard upper bound on `t` or `n`.
Practical bounds:

- `t = 1, n = 1`: degenerate single-party; works but is not a useful threshold.
- `t = 1, n > 1`: any single signer can produce the signature; not useful for custody.
- `t = n`: full-quorum requirement; works but loses fault tolerance.
- `t < n` (typical): the useful case.

Tested-as-of-this-revision profiles (per `bls_test.go`):
- 2-of-3
- 3-of-5

Performance benchmarks for larger profiles are gathered in
`~/work/lux/threshold/CLAUDE.md` (the parent threshold library's
benchmark table). Threshold-BLS specifically:

| Operation | 3-of-5 | 5-of-9 | 7-of-11 | 10-of-15 |
|---|---|---|---|---|
| Keygen (trusted dealer) | <5 ms | <10 ms | <15 ms | <30 ms |
| Per-party sign | <2 ms | <2 ms | <2 ms | <2 ms |
| Aggregate (`t` partials) | ~2 ms × `t` Lagrange mults + `t` G2 scalar-mults | scales linearly | scales linearly | scales linearly |
| Verify (aggregate) | ~2 ms (one pairing) | ~2 ms | ~2 ms | ~2 ms |

(Numbers indicative; exact values from the parent benchmark table.)

### §3.2 Party-ID constraints

Per `SPEC.md` §4.2:

- `party.ID` is a UTF-8 byte sequence.
- Its embedding into `F_r` via `party.ID(i).Scalar(F_r)` MUST be
  non-zero (else the share equals the master secret).
- IDs MUST be distinct across the party set (else Lagrange
  coefficients are undefined: division by zero in
  `Π (x_i − x_j)`).

The current implementation does NOT validate either constraint at
`Config` construction. Both are caller responsibilities until the
Tier-A gate in `PROOF-CLAIMS.md` §3.7 closes.

## §4 Encoding parameters

| Field | Size | Format |
|---|---|---|
| Public key (group + per-party VK) | 48 bytes | G1 compressed, IETF draft §2.5.1 |
| Secret key (master + per-party share) | 32 bytes | Big-endian scalar mod `r`, IETF draft §2.3 |
| Signature (partial + aggregate) | 96 bytes | G2 compressed, IETF draft §2.5.2 |
| Message | unbounded | Hashed via `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_` |

Threshold-specific wire formats (e.g., for the `pkg/thresholdd/`
dispatcher) are not yet pinned at this layer — see
`pkg/thresholdd/server.go` for the current RPC schema, which uses
hex-encoded byte strings for compatibility with the teleport-MPC
bus.

## §5 LP cross-reference

| LP | Title | Relation |
|---|---|---|
| LP-3653 | BLS12-381 Cryptography Precompile (legacy slot) | Single-party + aggregate; not threshold |
| LP-4110 | BLS12-381 Cryptography Precompile (canonical) | Single-party + aggregate; not threshold |
| LP-4700 | Threshold + MPC Family Umbrella | Indexes threshold protocols; threshold-BLS slot NOT YET ALLOCATED |
| LP-4710 | FROST Threshold Signature Precompile | Sibling threshold scheme |
| LP-4720 | CGGMP21 Threshold ECDSA Precompile | Sibling threshold scheme |

**Gap callout**: there is no LP for a `threshold-BLS precompile` at
this revision. A future LP would slot into the 4700-4799 range
adjacent to LP-4720. `SUBMISSION-STATUS.md` §3.3 enumerates this as
a Tier-A gate.

## §6 Profile selection rationale

Why BLS12-381 G2-signature ciphersuite (not G1-signature)?

- Lux uses BLS for **aggregate-friendly consensus signatures**. The
  G2-signature variant is canonical across Ethereum, Filecoin,
  Drand, dfinity, etc. — interop matters.
- The G1-signature variant trades a slightly smaller signature
  (48 bytes vs 96 bytes) for a larger public key (96 bytes vs
  48 bytes). For consensus-aggregation use cases, signature size
  amortizes, so the G2-signature variant is optimal.
- `luxfi/crypto/bls` pins the G2-signature ciphersuite. The
  threshold layer follows.

## §7 Parameter-change governance

Parameter changes (e.g., a future move to BLS12-377, a switch to
G1-signature variant, or any modification of the ciphersuite tag)
require:

1. A new LP under 4700-4799 specifying the change.
2. A new key-era boundary (no in-place modification of an existing
   committee).
3. A new test-vector set under `TEST-VECTORS.md` covering the new
   parameter combination.
4. A new sub-package or build tag — the existing package's behaviour
   never changes for an existing parameter set.

This is the **one-way-only forward** rule from the global CLAUDE.md.

## §8 References

- IETF `draft-irtf-cfrg-bls-signature-05` — encoding + ciphersuite.
- Boldyreva 2003 — threshold-BLS construction.
- `~/work/lux/lps/LPs/lp-4110-bls12-381-cryptography-precompile.md`.
- `~/work/lux/lps/LPs/lp-4700-threshold-mpc-family-umbrella.md`.
- `luxfi/crypto/bls` — single-party primitive (parameter pin).
- `cloudflare/circl/ecc/bls12381` — curve backend.

---

**Document metadata**

- Name: `PARAMS.md`
- Version: v0.1 (initial submission-package scaffolding)
- Date: 2026-05-18
