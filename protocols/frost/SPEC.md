# SPEC — FROST (Lux Profile)

> Construction-level spec for FROST (Flexible Round-Optimized
> Schnorr Threshold) as instantiated in the Lux ecosystem. The
> upstream construction is IETF/CFRG; this document pins the Lux
> profile and the integration contract.

## §1 Construction reference

The canonical construction is:

- **Komlo, C. and Goldberg, I.** *FROST: Flexible Round-Optimized
  Schnorr Threshold Signatures.* SAC 2020 / ePrint 2020/852.
- IETF: `draft-irtf-cfrg-frost` (latest published draft is the
  normative wire-format reference for Lux).

This document does NOT redefine FROST; it pins the Lux profile.

## §2 Lux profile

### 2.1 Pinned ciphersuites

The Lux ecosystem deploys exactly two ciphersuites:

| Ciphersuite | Group | Hash | LP |
|---|---|---|---|
| `FROST(Ed25519, SHA-512)` | edwards25519 | SHA-512 | LP-4711 |
| `FROST(secp256k1, SHA-256) + Taproot` | secp256k1 | SHA-256 | LP-4712 |

Other ciphersuites in the CFRG draft (P-256, ristretto255) are NOT
deployed in Lux profile v1. A future LP may add them; until then
they are out of scope.

### 2.2 Wire format

Wire format follows `draft-irtf-cfrg-frost` exactly. The Lux profile
adds NO wire-format modifications.

### 2.3 Threshold ranges

| Ciphersuite | Min `t` | Max `n` |
|---|---|---|
| Ed25519 | 2 | 1024 |
| secp256k1-Taproot | 2 | 1024 |

Configurations outside these ranges are rejected by `keygen/`.

### 2.4 Identifiable abort

The Lux profile mandates Komlo-Goldberg identifiable abort: round-2
signature shares are individually verifiable; misbehaving signers
are blamable via the per-share verification equation.

### 2.5 Dynamic resharing

Dynamic resharing is provided via the LSS adapter
(`threshold/protocols/lss/lss_frost.go`). The group public key
persists across resharing; rotated parties surrender their old
shares.

## §3 Integration contract

### 3.1 Round-state machine

FROST sessions live inside `internal/round` round-state machines
that govern message I/O, transcript binding, and abort handling.

### 3.2 Party identification

`PartyID` is a Lux-canonical 32-byte identifier (see
`internal/party`). Mapping to ciphersuite-specific keys is done at
session construction time.

### 3.3 Transcript binding

The Lux profile binds session transcripts via
`internal/hash`-domain-separated tags using:

- `lux-frost-ed25519-v1`
- `lux-frost-secp256k1-taproot-v1`

This domain separation prevents cross-ciphersuite replay.

## §4 What this spec does NOT cover

- The underlying FROST construction's security proof — see Komlo-
  Goldberg 2020 + the latest CFRG draft.
- The Ed25519 or secp256k1 primitive — see `luxfi/crypto/curve25519`
  and `luxfi/crypto/secp256k1`.
- Implementation correctness vs the construction — see
  `PROOF-CLAIMS.md` (honest scope).
- The submission tarball cut process — see `SUBMISSION-STATUS.md`.

## §5 Open spec items

- **Single-doc consolidation.** This SPEC.md + the upstream CFRG
  draft + LP-4711/LP-4712 are the spec surface. A future `spec/
  frost-lux.tex` consolidating these is a v0.X roadmap item.
- **Parameter-set worksheet.** See `PARAMS.md` for the current
  pinned ranges; tighter bounds with formal soundness margins are
  pending the v0.X-formal-methods milestone (out of scope for Tier B).

## §6 Cross-references

- `README.md` — overview
- `SUBMISSION-STATUS.md` — tier framework + gating
- `PROOF-CLAIMS.md` — honest non-claims
- `PARAMS.md` — pinned ciphersuites + ranges
- `TEST-VECTORS.md` — KAT format
- `SECURITY.md` — threat model
- LP-4710 / LP-4711 / LP-4712 / LP-4700
