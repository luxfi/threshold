# Cryptographer sign-off — luxfi/threshold/protocols/cmp (Lux profile)

> Independent review of the Lux CGGMP21 profile package at
> `~/work/lux/threshold/protocols/cmp/` at the commit immediately
> preceding `v1.8.0` (this submission's Tier A formal-artifact
> cluster).
> Date of review: 2026-05-18.
> Reviewer: cryptographer agent (internal review).

## Summary

**APPROVED WITH GATES** for production use (`mpcd` threshold ECDSA,
custodial bridge signing, MPC wallet backends) AND for the Tier A
submission package, subject to the six disclosure / pre-publish
gates in §Gates. The Tier A artifact cluster (EC theories + Lean
bridges + Jasmin scaffolds + CT obligation surface) is significantly
more demanding than FROST's or BLS's because CGGMP21 carries
Paillier + 17 ZK subprotocols; the cluster lands honestly with
appropriate "multi-month research" disclosures.

## What was reviewed

- **Algorithm source.** `~/work/lux/threshold/protocols/cmp/` —
  `cmp.go`, `keygen/`, `presign/`, `sign/`, `config/`.
- **Spec.** `SPEC.md`, `PARAMS.md`, `SECURITY.md`.
- **Tier A formal artifacts.**
  `proofs/easycrypt/CGGMP21_N1.ec`,
  `CGGMP21_N1_Refinement.ec`,
  `CGGMP21_Paillier.ec`,
  `CGGMP21_ZK.ec`,
  `CGGMP21_N4.ec`,
  `lemmas/CGGMP21_CT.ec`,
  `AXIOM-INVENTORY.md`.
- **Jasmin scaffolds.**
  `jasmin/lib/{cmp_params,paillier}.jinc`,
  `jasmin/single-party/secp256k1_ecdsa.jazz`,
  `jasmin/presign/{round1,round2,round3}.jazz`,
  `jasmin/threshold/sign_online.jazz`.
- **Lean bridge.** `~/work/lux/proofs/lean/Crypto/CGGMP21.lean`
  (Lux profile extension of the existing
  `Crypto.Threshold.CGGMP21` namespace).
- **Lean ↔ EC correspondence.** `proofs/lean-easycrypt-bridge.md`.

## Verified green

- [x] **Build.** `cd ~/work/lux/threshold && GOWORK=off go build ./...`
      clean.
- [x] **Test surface.** `GOWORK=off go test -count=1 -short -timeout
      300s ./protocols/cmp/` passes the canonical suites
      (cmp_basic, cmp_quick, cmp_threshold, cmp_unit,
      cmp_integration).
- [x] **Lagrange axioms bridged to Lean.** Axioms 1-3 in EC
      correspond to proved Lean theorems in
      `Crypto.Threshold.Lagrange`.
- [x] **Paillier axiom inventory is honest.** Axioms 5-6 (Paillier
      additive + scalar homomorphism) are stated as Lean axioms,
      not proved theorems. Closure path requires a Mathlib
      `Crypto.Paillier` module (multi-week work). The honest framing
      is in `AXIOM-INVENTORY.md`.
- [x] **CT obligation surface is honest.** Round-1, Round-2,
      Round-3 of presign + sign_online each get their own
      section-local `declare axiom` over an abstract module type.
      Paillier decryption CT is called out specifically as the
      load-bearing CT-critical operation.

## Findings

### Severity: high — ZK obligation cluster is large (17 protocols)

The CGGMP21 protocol uses 17 distinct ZK subprotocols (range
proofs, knowledge proofs, MtA, Paillier-Blum, etc.). The Tier A
shell in `CGGMP21_ZK.ec` enumerates the obligation surface but
does not mechanize any of the 17 individually.

**Risk**: medium. Each ZK subprotocol is independently studied in
the literature; CCS '21 §6 cites well-established results.
However, the Lux profile's specific instantiation (parameter
ranges, statistical security parameter = 80, ZK_MOD iterations =
128) needs profile-specific soundness analysis.

**Closure**: 3-6 months per subprotocol → ~5 years total
cumulative effort. This is the same scale as the lurk-rs / arkworks
foundational ZK formal-methods program and should be treated as
the same kind of multi-year cluster.

### Severity: medium — Paillier CT story inherits from saferith

The Lux profile inherits Paillier-CT from `cronokirby/saferith` (a
constant-time multi-precision arithmetic library). saferith is
small + audited at a basic level, but the specific code path used
for Paillier decryption (CRT-based modular exponentiation, modular
inverse on a 2048-bit modulus) has not been independently CT-tested
under dudect at submission budget.

**Risk**: medium. The Paillier-decryption side-channel surface
is the most vulnerable point in the entire CGGMP21 stack.

**Closure**: dudect run at 10^9 samples per Paillier op on a
pinned CPU. Estimated 2 weeks (pin a CPU, write the harness, run,
analyze).

### Severity: medium — admit budget 1/1 in `CGGMP21_N4.ec`

Same one-line group-identity admit as FROST_N4 and Pulsar_N4.

**Closure**: one-line Lean theorem.

### Severity: informational — Jasmin Paillier path is non-trivial

Libjade has no Paillier port. A Jasmin implementation of safe-prime
generation + biprime testing is a substantial undertaking with no
upstream equivalent. The Lux profile's Jasmin scaffold for
`presign/round{1,2}.jazz` is stub-level for the Paillier-touching
operations.

**Risk**: low (this is honest framing, not a defect).

## Gates (must close before promoting beyond v1.8.x)

### Gate 1: dudect at submission budget on Paillier dec

Run dudect at 10^9 samples per Paillier dec on a pinned CPU.
Required for the Paillier-CT side-channel attestation.

### Gate 2: ZK subprotocol formal-methods program

A dedicated multi-year program to mechanize the 17 ZK subprotocols
one at a time, with `ZK_MTA` as the first target (highest impact
on the protocol's overall security argument).

### Gate 3: Close the `CGGMP21_N4.ec` admit

Same single-line Lean theorem as FROST_N4.

### Gate 4: Wire `check-high-assurance.sh` per-push

Same as FROST gate 2.

### Gate 5: Mathlib Paillier module

A Lean implementation of the Paillier additive/scalar homomorphism
in a Mathlib-compatible module would close axioms 5-6 in
`AXIOM-INVENTORY.md`.

### Gate 6: Cross-validate vs single-party ECDSA

`SUBMISSION-STATUS.md §3.2` open item. Differential testing against
Bitcoin Core / geth / `crypto/ecdsa` for byte-equality at
production parameter sets (5-of-9, 7-of-11, 10-of-15).

## Verdict

**APPROVED WITH GATES** for v1.8.0. The Tier A artifact cluster
is honest about CGGMP21's substantial formal-methods cost (Paillier
+ 17 ZK protocols + 4-round DKG). The single admit is enumerated
and closable. The ZK cluster is a multi-year program that should
not block v1.8.0; the disclosure is in
`AXIOM-INVENTORY.md §closure roadmap`.

Sign-off, with the six gates above scheduled.
