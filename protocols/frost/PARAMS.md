# PARAMS — FROST (Lux Profile)

> Parameter-set registry for the Lux FROST profile. Pinned
> ciphersuites, threshold ranges, transcript-binding tags.

## §1 Pinned ciphersuites

The Lux profile deploys exactly two ciphersuites:

### 1.1 FROST(Ed25519, SHA-512)

| Field | Value |
|---|---|
| Group | edwards25519 (curve25519 Edwards form) |
| Group order | `2^252 + 27742317777372353535851937790883648493` |
| Hash | SHA-512 |
| Transcript-binding tag | `lux-frost-ed25519-v1` |
| Signature size | 64 bytes (compressed point + scalar) |
| LP | [LP-4711](https://github.com/luxfi/LPs/blob/main/LPs/lp-4711-frost-ed25519-ciphersuite.md) |
| Single-party verifier | `crypto/ed25519` (Go stdlib) |

### 1.2 FROST(secp256k1, SHA-256) + Taproot

| Field | Value |
|---|---|
| Group | secp256k1 |
| Group order | `2^256 - 432420386565659656852420866394968145599` (curve order n) |
| Hash | SHA-256 |
| Transcript-binding tag | `lux-frost-secp256k1-taproot-v1` |
| Signature size | 64 bytes (x-only point + scalar, BIP-340) |
| LP | [LP-4712](https://github.com/luxfi/LPs/blob/main/LPs/lp-4712-frost-secp256k1-taproot-ciphersuite.md) |
| Single-party verifier | BIP-340 Taproot verification |

## §2 Threshold ranges

Lux FROST instances must satisfy:

```
1 ≤ t ≤ n ≤ 1024
t ≥ 2     (single-signer is not a threshold scheme)
```

Configurations outside this range are rejected by `keygen/` with
a typed error.

### 2.1 Recommended operating points

| Use case | Pinned (t, n) | Rationale |
|---|---|---|
| Lux bridge custody | (3, 5) | High availability with 60% Byzantine tolerance |
| Validator multi-sig | (5, 7) | Maps to 5-of-7 Lux validator default |
| Federated DEX custody | (7, 10) | Wider committee, same tolerance |
| Cross-chain relay | (4, 7) | Matches `lss_frost.go` defaults |

These are recommendations, not normative. Deployments may choose
any `(t, n)` within §2.

## §3 Other parameters

### 3.1 Round count

FROST is a 2-round protocol:
- Round 1: commit (per-signer nonces)
- Round 2: reveal (per-signer signature shares)

The Lux profile does NOT add additional rounds.

### 3.2 Pre-processing (optional)

Round-1 commitments may be pre-computed in advance per Komlo-
Goldberg §6. The Lux production deployments do NOT use
pre-processing (round-1 commits are session-bound for replay
prevention); pre-processing is an opt-in flag.

### 3.3 Identifiable abort

Round-2 share verification is mandatory and enforced by `sign/`.
There is no opt-out.

## §4 Out-of-scope parameters

The following are CFRG draft parameters that the Lux profile pins
specifically and does NOT make configurable:

- Hash output truncation
- Nonce-generation entropy budget (mandated full-entropy per round)
- DKG protocol (Lux uses its own DKG via `keygen/` mirroring CFRG
  guidance, not a separate trusted-dealer mode)

## §5 Cross-references

- `SPEC.md` — protocol spec
- `README.md` — overview + Tier label
- LP-4710 / LP-4711 / LP-4712 / LP-4700
- Upstream: Komlo-Goldberg 2020 + `draft-irtf-cfrg-frost`
