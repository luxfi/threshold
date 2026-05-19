# Cryptographer sign-off — luxfi/threshold/protocols/bls (Lux profile)

> Independent review of the Lux threshold BLS profile package at
> `~/work/lux/threshold/protocols/bls/` at the commit immediately
> preceding `v1.8.0`.
> Date of review: 2026-05-18.
> Reviewer: cryptographer agent (internal review).

## Summary

**APPROVED WITH GATES** for production use (Quasar BLS finality,
shared-validator-set custodial signing, MPC wallet BLS path) AND
for the Tier A submission package, subject to the four disclosure /
pre-publish gates in §Gates. BLS-threshold has the smallest formal-
methods surface of the three classical threshold protocols — the
algebraic identity reduces to Lagrange + G2-distributivity, no
nonce sampling, no MtA, no Paillier, no ZK cluster.

## What was reviewed

- **Algorithm source.** `~/work/lux/threshold/protocols/bls/` —
  `bls.go` (all paths).
- **Spec.** `SPEC.md`, `PARAMS.md`, `SECURITY.md`,
  `PROOF-CLAIMS.md`.
- **Tier A formal artifacts.**
  `proofs/easycrypt/BLS_Threshold_N1.ec`,
  `BLS_Threshold_N1_Refinement.ec`,
  `BLS_Threshold_N4.ec`,
  `lemmas/BLS_Threshold_CT.ec`,
  `AXIOM-INVENTORY.md`.
- **Jasmin scaffolds.**
  `jasmin/lib/{bls_params,lagrange}.jinc`,
  `jasmin/single-party/bls12_381_sign.jazz`,
  `jasmin/threshold/{partial_sign,aggregate}.jazz`.
- **Lean bridge.** `~/work/lux/proofs/lean/Crypto/BLS.lean` (Lux
  profile extension under `Crypto.BLS.Threshold` namespace).
- **Lean ↔ EC correspondence.** `proofs/lean-easycrypt-bridge.md`.

## Verified green

- [x] **Build.** `cd ~/work/lux/threshold && GOWORK=off go build ./...`
      clean.
- [x] **Test surface.** `GOWORK=off go test -count=1 -short -timeout
      300s ./protocols/bls/` passes the canonical suites
      (bls_test.go).
- [x] **Lagrange axioms bridged to Lean.** Axioms 1-3 bridge to
      proved Lean theorems in `Crypto.Threshold.Lagrange`.
- [x] **G1/G2-distributivity axioms are honest.** Axioms 5-6
      (G2 scalar-mul distributivity, derive_pk homomorphism) are
      stated as Lean axioms; closure gated on a Mathlib BLS12-381
      module.
- [x] **CT obligation surface is minimal.** partial_sign is the
      only secret-touching procedure; aggregate is trivially CT.
      CT inheritance from `cloudflare/circl/ecc/bls12381`.
- [x] **No NIST overclaim.** `PROOF-CLAIMS.md §3.1` ("NOT proved:
      mechanized refinement") explicitly disclaims FIPS byte-
      equality (no FIPS BLS).

## Findings

### Severity: medium — DKG is trusted-dealer only

The Lux profile ships `TrustedDealer.GenerateShares` but no
publicly-verifiable DKG. Production deployments that require
DKG-equivalent guarantees rely on out-of-band trust in the dealer.

**Risk**: medium. For Quasar finality (validator set known + bonded)
the trusted-dealer model is acceptable; for cross-chain custody
the model is weaker.

**Closure**: `SUBMISSION-STATUS.md §3.3` open item. Implement
Pedersen-VSS over BLS12-381 (or import from
`luxfi/crypto/threshold/dkg`). Estimated 2-3 weeks.

### Severity: low — admit budget 1/1 in `BLS_Threshold_N4.ec`

Same one-line group-identity admit as FROST_N4 / CGGMP21_N4 /
Pulsar_N4.

**Closure**: one-line Lean theorem.

### Severity: informational — Jasmin BLS12-381 path is non-existent

Libjade has no BLS12-381 port. The Lux profile inherits CT from
circl. Jasmin scaffolds in `jasmin/single-party/` and
`jasmin/threshold/` are documentation stubs.

**Risk**: zero (matches honest framing).

## Gates (must close before promoting beyond v1.8.x)

### Gate 1: Implement DKG

Either Pedersen-VSS over BLS12-381 or import from the broader
luxfi crypto stack. Required for non-trusted-dealer deployments.

### Gate 2: Close the `BLS_Threshold_N4.ec` admit

Same one-line Lean theorem.

### Gate 3: Wire `check-high-assurance.sh` per-push

Shared script at `~/work/lux/threshold/scripts/check-high-
assurance.sh`.

### Gate 4: Cross-validate vs IETF draft test vectors

`SUBMISSION-STATUS.md §3.2` open item. Run the IETF
`draft-irtf-cfrg-bls-signature` reference vectors through the
threshold combine, assert byte-equality to the single-party
output. Estimated 1 week.

## Verdict

**APPROVED WITH GATES** for v1.8.0. BLS-threshold's Tier A
artifact cluster lands cleanly because the construction's
algebraic surface is small (Lagrange + G2 linearity). The single
admit is enumerated and closable. The DKG gap is a known
production constraint, disclosed in `SUBMISSION-STATUS.md §3.3`.

Sign-off, with the four gates above scheduled before v1.9.x.
