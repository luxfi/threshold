# SPEC — Threshold BLS (BLS12-381) — Lux profile

> **Standalone protocol specification** for the Lux-profile threshold
> BLS package at `github.com/luxfi/threshold/protocols/bls`.
>
> The cryptographic construction is the standard Shamir-shared BLS
> signature of Boldyreva 2003; this document pins the Lux profile
> (curve, ciphersuite, encoding, polynomial convention, party-ID
> embedding).

## §1 Scope

This document specifies the **Lux threshold BLS profile** as
implemented in `bls.go`. It covers:

- Curve, ciphersuite, encoding of the BLS12-381 base primitives.
- Shamir secret sharing convention (polynomial degree, field of
  evaluation, party-ID encoding).
- Per-party signing.
- Lagrange-coefficient combine.
- Aggregate verification.
- Trusted-dealer key generation surface (current).
- DKG (publicly-verifiable) — **NOT in this revision**; called out as
  a Tier-A gate in `SUBMISSION-STATUS.md`.

What this spec does **NOT** define:

- Single-party BLS signature / verify / public-key serialization —
  see `luxfi/crypto/bls` and IETF `draft-irtf-cfrg-bls-signature-05`.
- BLS12-381 curve arithmetic — see the `cloudflare/circl` library
  used as the curve backend.
- Threshold ECDSA (see `protocols/cmp/SPEC.md`).
- Threshold Schnorr (see `protocols/frost/SPEC.md`).

## §2 Terminology

| Term | Meaning |
|---|---|
| Party | A participant holding a single secret share. |
| `t` | Threshold (minimum quorum size; matches `Config.Threshold`). |
| `n` | Total parties (matches `Config.TotalParties`). |
| Sharing polynomial `f` | Degree `t − 1` polynomial over the BLS12-381 scalar field, constant term = master secret. |
| Group public key `PK` | `g1^s` where `s = f(0)`; bytes follow the BLS-G1 compressed encoding from `luxfi/crypto/bls`. |
| Per-party secret share `s_i` | `f(party.ID(i))` where `party.ID(i)` is interpreted as a non-zero scalar (see §4.2). |
| Per-party verification key `VK_i` | `g1^{s_i}`; published alongside the group PK. |
| Partial signature `σ_i` | Standard BLS signature `H(m)^{s_i}` produced by party `i`. |
| Aggregated signature `σ` | `Σ λ_i · σ_i` where `λ_i` is the Lagrange coefficient at `0` for the active quorum. |
| Lagrange coefficient `λ_i` | `Π_{j∈Q, j≠i} (0 − x_j) / (x_i − x_j)` over the scalar field. |

## §3 Curve and ciphersuite

| Parameter | Value | Source |
|---|---|---|
| Curve | BLS12-381 | `cloudflare/circl/ecc/bls12381` |
| Public-key group | G1 (48-byte compressed) | `luxfi/crypto/bls.PublicKey` |
| Signature group | G2 (96-byte compressed) | `luxfi/crypto/bls.Signature` |
| Pairing | `e: G1 × G2 → GT` | circl pairing |
| Hash-to-curve | `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_` | IETF `draft-irtf-cfrg-bls-signature-05` §4.2.2 (ciphersuite `_NUL_` augmentation handled by `luxfi/crypto/bls` `Sign`) |
| Scalar field `F_r` | `r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001` | BLS12-381 group order |

The ciphersuite identifier is inherited from `luxfi/crypto/bls`; the
threshold layer does **not** introduce a new ciphersuite tag. An
aggregated threshold signature is byte-indistinguishable from a
single-party BLS signature under this ciphersuite — that is the
load-bearing interop claim (§5.1).

## §4 Sharing scheme

### §4.1 Polynomial-degree convention

For a `t`-of-`n` configuration:

> The sharing polynomial `f` has **degree `t − 1`**.

This matches `bls.go:171`:

```go
poly := polynomial.NewPolynomial(blsCurve, d.Threshold-1, masterScalar)
```

Rationale: `t` evaluation points uniquely determine a polynomial of
degree `t − 1` via Lagrange interpolation; using degree `t` would
require `t + 1` shares to reconstruct.

### §4.2 Party-ID encoding

Party identifiers are `party.ID` strings (UTF-8 byte sequences). The
polynomial evaluation point for party `i` is the scalar
`party.ID(i).Scalar(blsCurve)` — a deterministic embedding of the
identifier bytes into the BLS12-381 scalar field `F_r`.

**Constraint**: `party.ID(i).Scalar(blsCurve) ≠ 0` for every party.
The implementation does not currently validate this on `Config`
construction; the trusted dealer `GenerateShares` will silently
produce a share equal to `f(0) = master_secret` for any party whose
ID maps to zero. This is a **must-not** in deployment. See
`SECURITY.md` §"Party-ID validity gate".

### §4.3 Lagrange combine

Aggregation runs in G2 (the signature group). For an active quorum
`Q` of exactly `t` signers:

```
σ = Σ_{i∈Q} λ_i(0) · σ_i        (G2 point addition; scalar mul by λ_i)
```

The implementation in `bls.go` truncates to the first `t` shares
when given more (`shares = shares[:threshold]`), which means the
caller is responsible for share selection. The aggregator does not
verify partial signatures before combining; see
`VerifyPartialSignature` for the explicit per-share verification
the caller should run first.

## §5 Security goals

### §5.1 Output interchangeability (Class N1 analogue)

> The aggregated signature `σ` produced by any honest threshold quorum
> on `(PK, m)` is byte-equal to the single-party BLS signature
> `BLS.Sign(s, m)` where `s = f(0)` is the master secret reconstructed
> from any `t` shares.

This is the property that makes the threshold scheme transparent to
any standard BLS verifier (FIPS-validated or otherwise).

**Trust base**:
- Algebraic correctness: Boldyreva 2003 §3 + Shamir 1979 secret
  sharing + Lagrange-coefficient identity in `F_r`.
- Implementation correctness: `bls.go:65 AggregateSignatures` matches
  the algebraic statement by code review + KAT cross-validation
  against `luxfi/crypto/bls.Verify`.

### §5.2 Unforgeability

Inherits `co-CDH` hardness in BLS12-381 (Boldyreva 2003 Theorem 1)
plus the random-oracle abstraction over the hash-to-curve.

**Not separately mechanized**. See `PROOF-CLAIMS.md` §3.

### §5.3 Rogue-key-attack resistance

The implementation does **not** currently require proof-of-possession
(PoP) at the threshold layer. The aggregate-signature attack surface
that motivates PoP (an adversary contributing a malicious public key
to subvert a sum) does not directly apply to Shamir-shared BLS
because every verification key `VK_i` is derived from a polynomial
whose constant term is the group public key — i.e., the `VK_i` set
is constrained by the polynomial commitment, not freely chosen by
each party.

**Caveat**: under the trusted-dealer flow this is enforced trivially
(the dealer constructs `VK_i = g_1^{f(i)}`). Under a future DKG, the
publicly-verifiable commitment to `f` must enforce the same
constraint or a separate rogue-key gate must be added. See
`SECURITY.md` §"Rogue-key under DKG".

## §6 Protocol surface (current implementation)

### §6.1 Trusted-dealer key generation

```go
type TrustedDealer struct { Threshold, TotalParties int }

func (d *TrustedDealer) GenerateShares(ctx, partyIDs) (
    shares       map[party.ID]*bls.SecretKey,
    groupPK      *bls.PublicKey,
    err          error,
)
```

Algorithmic flow:
1. Sample master secret key via `bls.NewSecretKey()` (CSPRNG).
2. Construct `f` of degree `t − 1` with `f(0) = master_secret`.
3. For each party `i`, compute `s_i = f(party.ID(i).Scalar(F_r))`.
4. Return `{s_i}_{i∈[n]}` plus `groupPK = g_1^{f(0)}`.

### §6.2 Per-party signing

```go
func (c *Config) Sign(message []byte) (*SignatureShare, error)
```

Runs `c.SecretShare.Sign(message)` — the standard `luxfi/crypto/bls`
single-party signing path. The threshold layer does **not** introduce
any nonce or hash difference vs single-party signing.

### §6.3 Combine

```go
func AggregateSignatures(shares []*SignatureShare, threshold int) (*bls.Signature, error)
```

See §4.3.

### §6.4 Verification

```go
func (c *Config) VerifyPartialSignature(share, message) bool
func (c *Config) VerifyAggregateSignature(message, sig) bool
```

Both delegate to single-party `bls.Verify` on `(VK_i, m, σ_i)` and
`(PK, m, σ)` respectively.

## §7 What is intentionally NOT in this spec

1. **Publicly-verifiable DKG** — current implementation uses a
   trusted dealer. A Pedersen-DKG over `F_r` with hiding blinds is
   a Tier-A gate (see `SUBMISSION-STATUS.md`).
2. **Proactive resharing** — no Refresh / ReshareToNewSet primitives.
   For lifecycle, see `protocols/lss/` (which can layer over this
   package once DKG lands).
3. **Identifiable abort** — Boldyreva-style threshold BLS is
   deterministic per-party; combine failure surfaces as
   "aggregated signature does not verify". Per-share verification
   localizes the malicious party but is a caller responsibility.
4. **Asynchronous network model** — synchronous assumption only.
5. **Hash-suite injection** — the BLS hash-to-curve is pinned to
   `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_` by the underlying
   `luxfi/crypto/bls` library; no Lux-side override.

## §8 References

- Boldyreva, A. *Threshold signatures, multisignatures and blind
  signatures based on the gap-Diffie-Hellman-group signature scheme.*
  PKC 2003. (Construction.)
- Boneh, D., Lynn, B., Shacham, H. *Short signatures from the Weil
  pairing.* ASIACRYPT 2001. (Single-party BLS.)
- IETF `draft-irtf-cfrg-bls-signature-05`. *BLS Signatures.*
  (Encoding, ciphersuite, hash-to-curve.)
- Shamir, A. *How to share a secret.* CACM 22(11), 1979.
- Lagrange interpolation over a finite field — textbook.
- `cloudflare/circl` BLS12-381 reference.
- Lux LP-4110 (BLS12-381 cryptography precompile) — single-party
  base primitive Lux already standardizes.

---

**Document metadata**

- Name: `SPEC.md`
- Version: v0.1 (initial submission-package scaffolding)
- Date: 2026-05-18
- Status: Tier B
