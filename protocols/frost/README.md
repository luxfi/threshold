# FROST — Lux-Profile Threshold Schnorr

> **Tier B — Lux-profile + integration spec gap.** Production
> implementation of FROST (Flexible Round-Optimized Schnorr
> Threshold) for the Lux ecosystem. Lux-profile submission package
> being assembled in this directory; readiness gated per
> `SUBMISSION-STATUS.md`.

## What this is

FROST is a 2-round threshold-Schnorr signature scheme. Threshold-`t`
of `n` parties produce a signature that verifies under the
single-party Schnorr verifier for the configured ciphersuite. Used
in the Lux ecosystem for:

- Cross-chain bridge custody (Cosmos Ed25519, Bitcoin Schnorr / Taproot)
- Account-abstracted multi-party wallets
- Validator-set threshold operations on non-PQ chains

## Code location

| Subdir | Content |
|---|---|
| `frost.go` | top-level orchestration |
| `keygen/` | distributed key generation |
| `sign/` | 2-round threshold signing |
| `frost_*_test.go` | unit, math, suite, threshold, sr25519, fixed tests |
| `frost_benchmark_test.go` | benchmarks |
| `scale_benchmark_test.go` | committee-size scaling |

Total: 20+ Go files, mature codebase.

## Ciphersuites

The Lux profile pins two ciphersuites:

| Ciphersuite | LP | Use case |
|---|---|---|
| **FROST(Ed25519, SHA-512)** | [LP-4711](https://github.com/luxfi/LPs/blob/main/LPs/lp-4711-frost-ed25519-ciphersuite.md) | Cosmos / Solana / SR25519 chains |
| **FROST(secp256k1, SHA-256, Taproot)** | [LP-4712](https://github.com/luxfi/LPs/blob/main/LPs/lp-4712-frost-secp256k1-taproot-ciphersuite.md) | Bitcoin Schnorr / Taproot |

See `PARAMS.md` for parameter-set details and threshold ranges.

## Tier label

**Tier B** — Lux-profile + integration spec gap. Upstream IETF/CFRG
draft (`draft-irtf-cfrg-frost`) is the construction; Lux adds the
profile pinning + Lux-specific KAT manifest + integration with the
threshold orchestration layer (`internal/round`, `internal/party`,
`pkg/protocol`) and the LSS dynamic-resharing wrapper (`lss/lss_frost.go`).

Compare to siblings:
- `luxfi/pulsar` — Tier A (mechanized refinement vs FIPS 204)
- `luxfi/corona` — Tier B (no FIPS anchor, honest no-proof disclosure)
- `protocols/frost` (this) — Tier B (upstream IETF draft is construction, Lux profile gap)
- `protocols/cmp` — Tier B
- `protocols/bls` — Tier B

## Dependencies

| Dep | Role |
|---|---|
| `luxfi/crypto/curve25519` (Ed25519 path) | underlying Ed25519 primitive |
| `luxfi/crypto/secp256k1` (Taproot path) | underlying secp256k1 + Schnorr primitive |
| `luxfi/threshold/internal/round` | round-state machine |
| `luxfi/threshold/internal/party` | party-id ordering, validation |
| `luxfi/threshold/internal/hash` | domain-separated hashing per ciphersuite |
| `luxfi/threshold/pkg/protocol` | protocol type system |

## Consumed by

- `luxfi/threshold/protocols/lss/lss_frost.go` — LSS-FROST adapter (dynamic resharing)
- `luxfi/mpc/` — production custody service
- `luxfi/threshold/cmd/threshold-cli/` — CLI

## Cross-references

- `SPEC.md` — construction spec + Lux profile
- `SUBMISSION-STATUS.md` — Tier B → A gating items
- `PROOF-CLAIMS.md` — honest scope (what's proved, what's not)
- `TEST-VECTORS.md` — KAT format + upstream CFRG vectors
- `SECURITY.md` — threat model + responsible disclosure
- `PARAMS.md` — ciphersuite + threshold range registry
- [LP-4710](https://github.com/luxfi/LPs/blob/main/LPs/lp-4710-frost-threshold-signature-precompile.md) — FROST precompile
- [LP-4711](https://github.com/luxfi/LPs/blob/main/LPs/lp-4711-frost-ed25519-ciphersuite.md) — Ed25519 ciphersuite
- [LP-4712](https://github.com/luxfi/LPs/blob/main/LPs/lp-4712-frost-secp256k1-taproot-ciphersuite.md) — secp256k1 Taproot
- [LP-4700](https://github.com/luxfi/LPs/blob/main/LPs/lp-4700-threshold-mpc-family-umbrella.md) — threshold-MPC family umbrella
