# CGGMP21 — Lux-Profile Threshold ECDSA

> **Tier B — Lux-profile + formal submission gap.** Production
> implementation of CGGMP21 (Canetti-Gennaro-Goldfeder-
> Makriyannis-Peled 2021) threshold-ECDSA over secp256k1. Lux-profile
> submission package being assembled in this directory; readiness
> gated per `SUBMISSION-STATUS.md`.

## What this is

CGGMP21 is a 4-round + presignature threshold-ECDSA signing scheme
that produces signatures byte-identical to single-party ECDSA on
secp256k1. Used in the Lux ecosystem for:

- Bitcoin custody (legacy ECDSA / P2PKH / P2SH)
- Ethereum / EVM-chain account control via threshold keys
- Cross-chain bridge custody to ECDSA-only chains
- Account abstraction with multi-party ECDSA wallets

## Code location

| Subdir | Content |
|---|---|
| `cmp.go` | top-level orchestration |
| `config/` | session configuration + parameter validation |
| `keygen/` | distributed key generation (4-round) |
| `presign/` | offline presignature generation (3-round) |
| `sign/` | online signing (1-round given presignature) |
| `cmp_*_test.go` | basic, benchmark, debug, integration, quick, threshold, unit tests |

Total: 30+ Go files, mature codebase.

## Tier label

**Tier B** — Lux-profile + formal submission gap. The CGGMP21 paper
(IACR ePrint 2020/492 → CCS 2021 → CGGMP21 = `draft` updates) is the
construction; Lux adds:

- secp256k1-pinned ciphersuite
- Lux-specific KAT manifest (roadmap)
- Integration with the threshold orchestration layer
- LSS dynamic-resharing wrapper (`lss/lss_cmp.go`)

Compare to siblings:
- `luxfi/pulsar` — Tier A (FIPS 204 mechanized refinement)
- `luxfi/corona` — Tier B (no FIPS anchor, honest no-proof)
- `protocols/cmp` (this) — Tier B (CCS '21 paper is construction, Lux profile gap)
- `protocols/frost` — Tier B
- `protocols/bls` — Tier B

## Dependencies

| Dep | Role |
|---|---|
| `luxfi/crypto/secp256k1` | underlying secp256k1 + ECDSA primitive |
| `luxfi/threshold/pkg/paillier` | Paillier encryption (used for MtA conversion) |
| `luxfi/threshold/pkg/pedersen` | Pedersen commitments |
| `luxfi/threshold/pkg/zk/*` | zero-knowledge subprotocols (affp, affg, dec, enc, fac, log, logstar, mod, mul, mulstar, nth, prm, sch, elog, encelg) |
| `luxfi/threshold/internal/round` | round-state machine |
| `luxfi/threshold/internal/party` | party-id ordering |
| `luxfi/threshold/internal/mta` | multiplicative-to-additive conversion |
| `luxfi/threshold/internal/ot` | oblivious transfer (Doerner variant) |

## Consumed by

- `luxfi/threshold/protocols/lss/lss_cmp.go` — LSS-CMP adapter (dynamic resharing)
- `luxfi/mpc/` — production custody service for ECDSA chains
- `luxfi/threshold/cmd/threshold-cli/` — CLI

## Why CGGMP21 and not GG18 / GG20

CGGMP21 (Canetti et al. 2021) is the construction successor to
Gennaro-Goldfeder (GG18, GG20). Lux deploys CGGMP21 because:

- **Identifiable abort** is constructive (unlike GG18)
- **UC-secure** under standard assumptions (unlike GG18)
- **Faster online signing** via offline presignature
- **Standard ECDSA output** — verifiable under Bitcoin, Ethereum,
  any secp256k1 ECDSA verifier without modification

## Cross-references

- `SPEC.md` — construction spec + Lux profile
- `SUBMISSION-STATUS.md` — Tier B → A gating items
- `PROOF-CLAIMS.md` — honest scope
- `TEST-VECTORS.md` — KAT format + paper reference vectors
- `SECURITY.md` — threat model
- `PARAMS.md` — secp256k1-specific parameters
- [LP-4720](https://github.com/luxfi/LPs/blob/main/LPs/lp-4720-cggmp21-threshold-ecdsa-precompile.md) — CGGMP21 precompile spec
- [LP-4730](https://github.com/luxfi/LPs/blob/main/LPs/lp-4730-dynamic-signer-rotation-with-lss-protocol.md) — LSS dynamic resharing
- [LP-4700](https://github.com/luxfi/LPs/blob/main/LPs/lp-4700-threshold-mpc-family-umbrella.md) — threshold MPC umbrella
