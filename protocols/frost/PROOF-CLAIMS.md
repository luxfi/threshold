# PROOF-CLAIMS — FROST (Lux Profile)

> **Honest scope.** This document states what the Lux FROST
> implementation HAS proved and explicitly enumerates what it has
> NOT proved. Mirrors `luxfi/corona/PROOF-CLAIMS.md §3` honesty
> template.

## §1 What is claimed

### 1.1 Construction correctness

The Lux FROST implementation realizes the construction defined in
Komlo-Goldberg (SAC 2020 / ePrint 2020/852) and the IETF CFRG draft
`draft-irtf-cfrg-frost` for the pinned ciphersuites (Ed25519,
secp256k1-Taproot).

**Evidence**:
- Unit + threshold test coverage across `frost_*_test.go` files
- Property tests under `frost_math_test.go` for the algebraic
  identity
- Cross-ciphersuite tests under `frost_sr25519_test.go`,
  `frost_standard_test.go`
- Integration tests via `lss_frost.go` exercising the LSS adapter

### 1.2 Wire-format conformance

Wire format follows `draft-irtf-cfrg-frost` exactly. KAT replay
tests fail on any deviation.

### 1.3 Identifiable abort

Round-2 signature shares are individually verifiable per Komlo-
Goldberg §5. Misbehaving signers are blamable; round-2 verification
is a hard invariant in `sign/`.

## §2 What is NOT claimed

This is the load-bearing honesty disclosure. The Lux FROST profile
explicitly does NOT claim:

### 2.1 No mechanized refinement proof

- No EasyCrypt theories
- No Lean bridges
- No Jasmin constant-time-verified sources
- No formal refinement against a NIST-standard verifier (FROST has
  no NIST verifier — N1 framing is not applicable)

Path to closure: `SUBMISSION-STATUS.md §3.5` (multi-month research).

### 2.2 No FIPS standard byte-equality

FROST is not a NIST standard. There is no FIPS verifier to be
byte-equal to. Cross-validation is against the CFRG draft +
upstream reference implementations.

### 2.3 No dudect-class CT analysis

No statistical constant-time harness has been run. The underlying
primitives (`luxfi/crypto/curve25519`, `luxfi/crypto/secp256k1`)
have their own CT posture; the threshold layer's CT story is
asserted by construction (no data-dependent branches on shares)
but not measured.

Path to closure: `SUBMISSION-STATUS.md §3.5` (Jasmin-CT or dudect).

### 2.4 No independent cryptographer sign-off

No formal sign-off doc (cf. Pulsar's CRYPTOGRAPHER-SIGN-OFF.md).
The construction's security is inherited from Komlo-Goldberg; the
Lux profile's correctness is asserted by tests + LP authorship.

Path to closure: `SUBMISSION-STATUS.md §3.6`.

### 2.5 No security analysis of the Lux profile deltas

Lux pins ciphersuites, transcript-domain-separation tags, and
threshold ranges. These deltas are NOT separately analyzed; they
follow the upstream construction without expected security
modification.

Path to closure: when a Lux-profile security memo is written.

## §3 Comparison to siblings

| Repo | Mechanized refinement | FIPS anchor | CT analysis | Sign-off |
|---|---|---|---|---|
| `luxfi/pulsar` | ✅ EC 13/13 + Lean 5/5 + Jasmin 3/3 | ✅ FIPS 204 byte-equal | dudect harness wired | ✅ APPROVED WITH GATES |
| `luxfi/corona` | ❌ no EC/Lean/Jasmin (honest gap) | ❌ no FIPS anchor (R-LWE) | ❌ no dudect | ❌ |
| `protocols/frost` (this) | ❌ no EC/Lean/Jasmin | ❌ no FIPS anchor (CFRG-only) | ❌ asserted by construction | ❌ |
| `protocols/cmp` | ❌ | ❌ | ❌ | ❌ |
| `protocols/bls` | ❌ | ❌ | ❌ | ❌ |

Pulsar is the **only** Lux primitive with Tier A maturity. FROST,
Corona, CMP, BLS are honestly Tier B.

## §4 What an external reviewer should read

A reviewer assessing FROST should read in this order:

1. `README.md` — purpose + tier label
2. `SPEC.md` — Lux profile pinning
3. `SUBMISSION-STATUS.md` — gating items + path to Tier A
4. `PROOF-CLAIMS.md` (this) — honest scope
5. `PARAMS.md` — ciphersuite + threshold ranges
6. `TEST-VECTORS.md` — KAT scope
7. `SECURITY.md` — threat model
8. Upstream: Komlo-Goldberg 2020 + `draft-irtf-cfrg-frost`
9. Code: `frost.go`, `keygen/`, `sign/` + tests

## §5 Cross-references

- `SUBMISSION-STATUS.md` — Tier B → A path
- `luxfi/corona/PROOF-CLAIMS.md` — honest disclosure template this file mirrors
- `luxfi/pulsar/PROOF-CLAIMS.md` — Tier A reference (what FROST does NOT yet have)
