# SPEC — CGGMP21 (Lux Profile)

> Construction-level spec for CGGMP21 threshold-ECDSA as instantiated
> in the Lux ecosystem. The upstream construction is the CCS '21
> paper; this document pins the Lux profile and the integration
> contract.

## §1 Construction reference

The canonical construction is:

- **Canetti, R., Gennaro, R., Goldfeder, S., Makriyannis, N., and
  Peled, U.** *UC Non-Interactive, Proactive, Threshold ECDSA with
  Identifiable Aborts.* CCS 2021. ePrint 2021/060.

This document does NOT redefine CGGMP21; it pins the Lux profile.

## §2 Lux profile

### 2.1 Pinned curve

Lux deploys CGGMP21 exclusively over **secp256k1**. P-256 and other
curves are out of scope; future LPs may add them.

### 2.2 Signature output

CGGMP21 produces signatures byte-identical to single-party ECDSA on
secp256k1. A standard secp256k1 ECDSA verifier (Bitcoin,
Ethereum, any RFC 6979-compatible verifier) accepts CGGMP21
threshold-produced signatures without modification.

### 2.3 Threshold ranges

| Range | Bound |
|---|---|
| Minimum `t` | 2 |
| Maximum `n` | 32 |

The upper bound of 32 reflects practical performance constraints
(Paillier operations per signing round scale quadratically). Above
32, signing latency exceeds operational windows.

### 2.4 Round structure

CGGMP21 has two phases:

| Phase | Rounds | Frequency |
|---|---|---|
| Keygen | 4 rounds | Once per party-set |
| Presign | 3 rounds | Per signature (offline) |
| Sign | 1 round | Per signature (online, given presignature) |

The presign phase is offline-precomputable; signing latency given a
ready presignature is one round.

### 2.5 Identifiable abort

CGGMP21 has constructive identifiable abort per paper §5. The Lux
profile mandates this; round-N signatures are individually
verifiable; misbehaving signers are blamable.

### 2.6 Dynamic resharing

Dynamic resharing is provided via the LSS adapter
(`protocols/lss/lss_cmp.go`). The group ECDSA public key persists
across resharing.

### 2.7 Refresh

CGGMP21's proactive refresh (paper §7) is supported via the same
LSS path. Refresh rotates secret shares while preserving the
group public key (no key delta).

## §3 Integration contract

### 3.1 Round-state machine

CGGMP21 sessions live inside `internal/round` round-state machines.

### 3.2 Party identification

`PartyID` is a Lux-canonical 32-byte identifier (see
`internal/party`). secp256k1-specific public-key mapping is done at
session construction time.

### 3.3 Transcript binding

Sessions bind via domain-separated tag:

- `lux-cmp-secp256k1-v1`

This prevents cross-curve / cross-protocol replay.

### 3.4 Paillier modulus

Each party generates a fresh Paillier modulus (`pkg/paillier`) at
keygen time. Modulus bit-length: **2048 bits** (matches CCS '21
recommendation).

### 3.5 Pedersen parameters

Per-party Pedersen parameters (`pkg/pedersen`) are derived at keygen
time as a side-effect of the Paillier-modulus generation. These are
used in the MtA zero-knowledge subprotocols.

### 3.6 Zero-knowledge subprotocols

The Lux profile uses the CCS '21 zero-knowledge primitives without
modification:

- `affg`, `affp`, `dec`, `enc`, `encelg`, `fac`, `log`, `logstar`,
  `mod`, `mul`, `mulstar`, `nth`, `prm`, `sch`, `elog`

All live under `pkg/zk/*` in the threshold orchestration repo.

## §4 What this spec does NOT cover

- The CGGMP21 construction's security proof — see CCS '21.
- The secp256k1 primitive — see `luxfi/crypto/secp256k1`.
- The Paillier encryption scheme — see `pkg/paillier` README.
- Implementation correctness vs the construction — see
  `PROOF-CLAIMS.md` (honest scope).

## §5 Open spec items

- **Single-doc consolidation.** This SPEC.md + the CCS '21 paper +
  LP-4720 are the spec surface. A future `spec/cmp-lux.tex`
  consolidating these is a v0.X roadmap item.
- **Performance worksheet.** Per-round latency and CPU cost under
  the pinned parameter set need a measured-vs-paper table.

## §6 Cross-references

- `README.md`, `SUBMISSION-STATUS.md`, `PROOF-CLAIMS.md`,
  `PARAMS.md`, `TEST-VECTORS.md`, `SECURITY.md` — companion docs
- LP-4720 / LP-4730 / LP-4700
- Upstream: CCS '21 + ePrint 2021/060
