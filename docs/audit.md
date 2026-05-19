# Security Audit Status

This document describes the current security-review posture of the
`luxfi/threshold` library and tracks the status of external audits.
It resolves [#5](https://github.com/luxfi/threshold/issues/5) by making
the audit state explicit instead of linking to a missing document.

## TL;DR

| Component                               | Status                                    |
| --------------------------------------- | ----------------------------------------- |
| **External third-party audit**          | ❌ Not yet commissioned                    |
| **Internal review**                     | ✅ Ongoing — tracked in this repo          |
| **Upstream primitive audits**           | ✅ See *Upstream audits* below             |
| **Responsible-disclosure process**      | ✅ `security@lux.network`                  |

> **Do not deploy this library to mainnet custodying user funds without
> performing — or commissioning — your own security review.** The
> production-readiness badges in the README refer to test coverage,
> correctness testing, and internal review; they are **not** a substitute
> for an external cryptographic audit.

## Scope of this repository

The library implements several threshold-signature protocols, each with
distinct trust assumptions and failure modes:

- **CMP** — ECDSA, 4-round online / 7-round presigning, identifiable aborts.
- **FROST** — Schnorr/EdDSA, BIP-340 Taproot compatible.
- **LSS** — ECDSA with dynamic resharing.
- **Doerner** — 2-of-2 ECDSA.
- **Unified** — chain-adapter layer.

Each protocol has its own security proof in the literature; correctness of
this implementation against those proofs is the subject of internal review
and will be the subject of external audit.

## Upstream audits

Several building blocks are taken from — or closely track — implementations
that have themselves been audited. Those audits cover the primitive, not
its use in this library:

- **secp256k1** — curve operations use the audited `decred/dcrd/dcrec`
  package.
- **Paillier encryption / ZK proofs** — adapted from
  `taurushq-io/multi-party-sig`, which follows the CMP20 specification.
- **Edwards-curve Ed25519** — `filippo.io/edwards25519`.
- **Blake3** — `lukechampine.com/blake3`.

If you are depending on one of these primitives in isolation, consult the
upstream audit directly.

## Internal review

- 100% line coverage on `protocols/lss`, `protocols/frost`,
  `protocols/unified`, `protocols/doerner`; 75%+ on `protocols/cmp`.
- Concurrent-signing fuzz and race tests in `internal/test/`.
- Known side-channel considerations (constant-time scalar arithmetic,
  no data-dependent branching on secret material) documented in code
  comments next to the relevant operations.

## Known limitations

- **Network layer is out of scope.** The library expects the caller to
  supply authenticated, confidential channels between parties. The
  provided `internal/test.Network` is for tests only.
- **Identifiable abort** in CMP relies on all parties running the
  reference implementation. A malicious party running a modified
  implementation may cause an abort without being identifiable.
- **HSM-compatible** in the README means the wire format is compatible
  with typical HSM APIs; no HSM vendor has certified this library.

## Responsible disclosure

Report vulnerabilities privately to **security@lux.network**. Please do
not open a public issue for suspected security bugs. We will acknowledge
receipt within 72 hours and aim to confirm or reject the report within
10 business days.

## Audit log

External audits will be listed here once completed.

| Date | Auditor | Scope | Report |
| ---- | ------- | ----- | ------ |
| —    | —       | —     | —      |
