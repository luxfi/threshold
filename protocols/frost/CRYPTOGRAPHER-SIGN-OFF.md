# Cryptographer sign-off — luxfi/threshold/protocols/frost (Lux profile)

> Independent review of the Lux FROST profile package at
> `~/work/lux/threshold/protocols/frost/` at the commit immediately
> preceding `v1.8.0` (this submission's Tier A formal-artifact
> cluster).
> Date of review: 2026-05-18.
> Reviewer: cryptographer agent (internal review).

## Summary

**APPROVED WITH GATES** for production use under the existing FROST
deployment (`mpcd` threshold-listen, `lss` adapter, custodial wallet
backends) AND for the Tier A submission package, subject to the
five disclosure / pre-publish gates in §Gates. The Tier A artifact
cluster (EC theories + Lean bridges + Jasmin scaffolds + CT
obligation surface) lands honestly: the protocol-level reduction
mirrors Pulsar's structure with the appropriate adaptations for
Schnorr (vs Module-LWE), no FIPS analogue is overclaimed, and the
admit budget is enumerated in `proofs/easycrypt/AXIOM-INVENTORY.md`.

## What was reviewed

- **Algorithm source.** `~/work/lux/threshold/protocols/frost/` —
  `frost.go`, `keygen/{round1,round2,round3,keygen,config}.go`,
  `sign/{round1,round2,round3,sign,types}.go`.
- **Spec.** `~/work/lux/threshold/protocols/frost/SPEC.md`,
  `PARAMS.md`, `SECURITY.md`.
- **Tier A formal artifacts.** `proofs/easycrypt/FROST_N1.ec`,
  `FROST_N1_Refinement.ec`, `FROST_Ciphersuite_Ed25519.ec`,
  `FROST_Ciphersuite_Secp256k1_Taproot.ec`, `FROST_N4.ec`,
  `lemmas/FROST_CT.ec`, `AXIOM-INVENTORY.md`.
- **Jasmin scaffolds.** `jasmin/lib/{frost_params.jinc,
  transcript.jinc, lagrange.jinc}`,
  `jasmin/single-party/{ed25519_sign.jazz,
  secp256k1_bip340.jazz}`, `jasmin/threshold/{round1.jazz,
  round2.jazz, combine.jazz}`.
- **Lean bridge.** `~/work/lux/proofs/lean/Crypto/FROST.lean` (this
  submission extends the existing file with the Lagrange-algebraic
  bridge).
- **Lean ↔ EC correspondence.** `proofs/lean-easycrypt-bridge.md`.

## Verified green

- [x] **Build.** `cd ~/work/lux/threshold && GOWORK=off go build ./...`
      runs clean against `protocols/frost/`.
- [x] **Test surface.** `GOWORK=off go test -count=1 -short -timeout
      300s ./protocols/frost/` passes the canonical FROST suites
      (frost_threshold_test, frost_unit_test, frost_standard_test,
      frost_sr25519_test, frost_math_test) for both pinned
      ciphersuites.
- [x] **Lagrange axioms bridged to Lean.** Each of the four EC
      axioms in `proofs/easycrypt/FROST_N1.ec` corresponds 1:1 to
      a proved Lean theorem in `Crypto.FROST.Lagrange` /
      `Crypto.Threshold.Lagrange`. Citations enforced by
      `~/work/lux/threshold/scripts/check-high-assurance.sh`.
- [x] **Ciphersuite layer is honest.** Two pinned ciphersuites
      (Ed25519 + secp256k1-BIP340) get their own EC files with
      explicit byte-encoding axioms tied to RFC 8032 / BIP-340.
      No vacuous polymorphism — each pinned ciphersuite is
      individually byte-validated.
- [x] **CT obligation surface mirrors Pulsar.** Round-1 (nonce
      sampling) and Round-2 (response computation) each get a
      `declare axiom` over an abstract `CTRound{1,2}` module type.
      Combine is trivially CT (no secret inputs). Mirrors
      `pulsar/proofs/easycrypt/lemmas/Pulsar_CT.ec`.
- [x] **No FIPS overclaim.** `PROOF-CLAIMS.md §2.2` ("No FIPS
      standard byte-equality") and `SUBMISSION-STATUS.md §2`
      ("FROST is not a NIST MPTC primary candidate") remain in
      force. The N1 framing in `FROST_N1.ec` is explicit about
      "Lux-profile analogue of Pulsar's Class N1", not "FIPS
      byte-equality".

## Findings

### Severity: medium — admit budget 1/1 in `FROST_N4.ec`

The proof of `frost_n4_pk_preservation_honest` (public-key
preservation across honest refresh) closes the Lagrange-zero-share
sum by `reconstruct_linear_N4` + `shamir_correct_N4` +
`derive_pk_homomorphism` + `derive_pk_zero`. The final step is a
one-line group-identity rewrite (`group_pk_add P group_zero_pk =
P`) that is left as a deferred `admit` pending a small extension
to the Lean `FROST.lean` module.

**Risk**: low. The identity is trivial in any abstract group
theory.

**Closure**: one-line Lean theorem (`derive_pk_group_identity`) in
`Crypto.FROST.lean`. Estimated 1 day of Lean work; this is the
single non-shipped piece of the v1.8.0 → v1.8.1 closure.

### Severity: informational — Jasmin compile gate is advisory

The `jasmin/threshold/*.jazz` files ship algorithm signatures and
algorithm commentary as stubs (`// TODO: jasmin implementation`).
This matches the Pulsar Tier A pre-implementation-cleanup state.

**Risk**: zero for the Tier A artifact (the EC theories are
self-contained; the Jasmin compile gate is skip-clean when sources
are stubs). Risk for the long-term high-assurance closure is
**multi-month implementation** plus libjade-port-of-Ed25519 (which
does not yet exist upstream).

**Closure**: tracked in `SUBMISSION-STATUS.md §3.5`.

## Gates (must close before promoting beyond v1.8.x)

### Gate 1: Close the `FROST_N4.ec` admit

Add `derive_pk_group_identity` to `Crypto.FROST.lean` and link it
into `FROST_N4.ec`. One-line theorem, one-day work.

### Gate 2: Wire `check-high-assurance.sh` per-push

The shared threshold gate script at
`~/work/lux/threshold/scripts/check-high-assurance.sh` lists
FROST's bridge axioms but is not yet wired into CI. Wire it.

### Gate 3: Differential interop vs CFRG reference vectors

`SUBMISSION-STATUS.md §3.2` open item. Cross-validate against
`cfrg/draft-irtf-cfrg-frost` reference vectors for both pinned
ciphersuites. Estimated 1 week.

### Gate 4: Implement (or honestly skip) Jasmin threshold layer

Either (a) port `threshold/{round1,round2,combine}.jazz` to real
implementations once libjade ports Ed25519 + secp256k1 ciphersuites,
OR (b) document the Go-reference CT inheritance from `crypto/ed25519`
/ `cloudflare/circl/secp256k1` explicitly in
`PROOF-CLAIMS.md §2.3`.

### Gate 5: dudect at submission budget

Run dudect at 10^9 samples on the Round-1 + Round-2 routines on
the Go reference. Pulsar's `ct/dudect/` template applies.

## Verdict

**APPROVED WITH GATES** for v1.8.0. The Tier A artifact cluster is
load-bearing, honest, and lands without overclaiming. The single
admit is enumerated and closable; the Jasmin scaffolds match the
Pulsar Tier A pre-implementation state honestly.

Sign-off, with the five gates above scheduled before v1.9.x.
