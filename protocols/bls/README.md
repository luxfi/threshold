# threshold-BLS (BLS12-381) — Lux profile package

> **Tier B — Lux-profile + integration spec gap.** The implementation
> exists and compiles; the NIST/IETF submission package is being
> assembled in this directory. See `SUBMISSION-STATUS.md` for the
> path to Tier A.

## One-line purpose

Threshold BLS over BLS12-381: a `t`-of-`n` Shamir-shared BLS signing
scheme whose aggregated output is a single BLS signature byte-equal to
the signature a single-party holder of the reconstructed secret would
produce — verifiable by any standard BLS verifier without
threshold-aware code.

## What this directory is

This is the **Lux-profile package** for threshold BLS — the
implementation lives here, plus the submission-shaped documentation
set that mirrors `~/work/lux/corona/`'s Tier B scaffold (cover,
spec, proof claims, status, test vectors, security, params).

The underlying constructions are NOT Lux inventions:

- **Single-party BLS**: Boneh-Lynn-Shacham 2001 + IETF
  `draft-irtf-cfrg-bls-signature-05`.
- **Threshold BLS**: Boldyreva 2003 (*Threshold signatures, multisignatures
  and blind signatures based on the gap-Diffie-Hellman-group signature
  scheme*) — Shamir sharing of the BLS secret + Lagrange aggregation of
  per-party BLS signatures.

What Lux adds is the **profile**: party-ID encoding, polynomial-degree
convention (`t − 1`), curve binding (BLS12-381 G1 keys / G2 sigs per
`luxfi/crypto/bls` ciphersuite), integration with the unified threshold
RPC at `pkg/thresholdd/`, and the KAT / interop / security plumbing
necessary for NIST-style submission packaging.

## Status

| Aspect | Status |
|---|---|
| Implementation | Production (consumed by Quasar BLS leg via `pkg/thresholdd`) |
| Tier label | **B** — Lux-profile docs + integration spec gap |
| Code surface | 2 files, ~386 LOC: `bls.go` + `bls_test.go` |
| KAT determinism | Not yet enforced cross-runtime (no `cmd/bls_oracle/`) |
| Interop tests | Inherited from `luxfi/crypto/bls` BLS suite (BLS-G1-KEYS / BLS-G2-SIG ciphersuite) |
| Formal proof tier | None at this revision — see `PROOF-CLAIMS.md` §3 |

## Where the code lives

```
protocols/bls/
  bls.go               -- Config, TrustedDealer, Sign, AggregateSignatures, Verify*
  bls_test.go          -- unit tests (2-of-3, 3-of-5 happy paths)
```

Cross-referenced from:

```
pkg/thresholdd/        -- exposes bls.{keygen,sign,verify} over JSON-RPC
                          (canonical dispatcher; consumed by mpcd)
```

## Dependency graph

```
protocols/bls
   ├── github.com/luxfi/crypto/bls      (single-party BLS, BLS12-381 sig/verify)
   ├── github.com/cloudflare/circl       (BLS12-381 curve arithmetic, G2 points)
   ├── threshold/pkg/math/curve          (BLS12381G1 scalar field, polynomial eval)
   ├── threshold/pkg/math/polynomial     (Shamir polynomial + Lagrange coefficients)
   └── threshold/pkg/party               (party.ID encoding into the scalar field)
```

No cycles. The `luxfi/crypto/bls` package is the only upstream BLS
primitive surface; threshold logic is layered on top.

## What this submission package proves (and does not)

See `PROOF-CLAIMS.md`. Short version:

- ✓ Implementation matches Boldyreva 2003 + IETF BLS draft + Shamir-Lagrange
  algebra (by code review + KAT cross-validation against `luxfi/crypto/bls`).
- ✓ Aggregated signature byte-verifies against any standard BLS verifier.
- ✗ No EasyCrypt theory, no Lean bridge, no Jasmin sources.
- ✗ No DKG — current implementation uses a `TrustedDealer`. Publicly-
  verifiable DKG is a Tier-A gate (see `SUBMISSION-STATUS.md`).
- ✗ No rogue-key-attack proof-of-possession ceremony at the threshold
  layer (single-party `luxfi/crypto/bls` handles PoP for the aggregate-
  signature case; threshold case binds at the verification-share level).

## Honest gap callout

No LP currently exists for the threshold-BLS precompile. The
classical BLS12-381 precompiles are LP-3653 / LP-4110 (single-party
+ aggregate, not threshold). The umbrella LP-4700 lists slots for
threshold-FROST (4710-4712) and threshold-ECDSA (4720) but does not
yet allocate a slot for threshold-BLS. A future LP would slot into
the 4700-4799 range alongside LP-4720. This package is currently
consumed only via the in-process `thresholdd` dispatcher; no
EVM-precompile path is wired yet.

## How to reproduce

```bash
cd ~/work/lux/threshold
GOWORK=off go test ./protocols/bls/...
```

KAT vectors and the cross-runtime byte-equality plumbing are
roadmap items — the Tier A path in `SUBMISSION-STATUS.md` enumerates
the missing pieces.

## Specification

See `SPEC.md` for the protocol-level specification.
See `PARAMS.md` for the parameter-set worksheet.
See `SECURITY.md` for threat model + responsible-disclosure pointer.
See `TEST-VECTORS.md` for KAT format and upstream-vector sources.

## License

Apache-2.0 (matches the parent `luxfi/threshold` repository).
