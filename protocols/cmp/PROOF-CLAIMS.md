# PROOF-CLAIMS — CGGMP21 (Lux Profile)

> **Honest scope.** Mirrors `corona/PROOF-CLAIMS.md §3` template.

## §1 What is claimed

### 1.1 Construction correctness

The Lux CGGMP21 implementation realizes the construction defined in
Canetti-Gennaro-Goldfeder-Makriyannis-Peled (CCS 2021 / ePrint
2021/060) for secp256k1.

**Evidence**:
- Unit + threshold test coverage across `cmp_*_test.go` files
- Integration tests under `cmp_integration_test.go`
- Quick + threshold tests covering 2-of-3 through 20-of-32
  configurations

### 1.2 Byte-identical to single-party ECDSA

The signature output verifies byte-identical under any single-party
secp256k1 ECDSA verifier (`crypto/ecdsa`, Bitcoin Core ECDSA,
Ethereum/geth ECDSA).

This is the analogue of Pulsar's FIPS 204 byte-equality claim, but
for ECDSA rather than ML-DSA. Critical for bridge / custody use
cases where the receiving chain runs an unmodified secp256k1 ECDSA
verifier.

### 1.3 Identifiable abort

Round-N signature shares + ZK subprotocols are individually
verifiable per CCS '21 §5. Misbehaving signers are blamable.

### 1.4 Paillier soundness checks

Biprime testing per CCS '21 Appendix C is implemented at keygen
time (in `pkg/paillier`).

## §2 What is NOT claimed

### 2.1 No mechanized refinement proof

- No EasyCrypt theories
- No Lean bridges
- No Jasmin constant-time-verified sources
- No formal refinement against a NIST-standard verifier (NIST has
  not standardized threshold-ECDSA)

Path to closure: `SUBMISSION-STATUS.md §3.7` (multi-month research).

### 2.2 No dudect-class CT analysis

The threshold layer's constant-time story is asserted by
construction (no data-dependent branches on secret shares or
nonces) but not statistically measured. The underlying secp256k1
primitive (`luxfi/crypto/secp256k1`) has its own CT posture.

Path to closure: SUBMISSION-STATUS.md §3.7.

### 2.3 No independent cryptographer sign-off

No formal sign-off doc (cf. Pulsar's CRYPTOGRAPHER-SIGN-OFF.md).
The construction's security is inherited from CCS '21; the Lux
profile's correctness is asserted by tests + LP authorship.

Path to closure: SUBMISSION-STATUS.md §3.8.

### 2.4 No formal Paillier-modulus audit

Biprime testing is implemented but has NOT been audited against
CCS '21 Appendix C exhaustively, especially the Blum-prime property
required for the ZK subprotocols.

Path to closure: SUBMISSION-STATUS.md §3.3.

### 2.5 No security analysis of the Lux-profile deltas

Lux pins the curve (secp256k1), Paillier modulus size (2048), and
transcript-binding tag. These deltas are NOT separately analyzed.

### 2.6 No UC-game implementation in code

CGGMP21's UC framework guarantees are paper-side; the Lux
implementation realizes the construction but does not codify the
UC simulator. Mechanizing the UC argument is part of §3.7.

## §3 Comparison to siblings

| Repo | Mechanized refinement | Standard byte-equal | CT analysis | Sign-off |
|---|---|---|---|---|
| `luxfi/pulsar` | ✅ EC + Lean + Jasmin | ✅ FIPS 204 | dudect wired | ✅ APPROVED WITH GATES |
| `luxfi/corona` | ❌ honest gap | ❌ no FIPS anchor | ❌ | ❌ |
| `protocols/cmp` (this) | ❌ | ✅ secp256k1 ECDSA byte-equal | ❌ | ❌ |
| `protocols/frost` | ❌ | ✅ ciphersuite verifier | ❌ | ❌ |
| `protocols/bls` | ❌ | ✅ BLS aggregate verifier | ❌ | ❌ |

CMP, FROST, and BLS all share the "byte-identical to single-party
verifier" property (analogous to Pulsar's N1 claim) but lack the
mechanized refinement that Pulsar has.

## §4 What an external reviewer should read

1. `README.md` — purpose + tier label
2. `SPEC.md` — Lux profile pinning + secp256k1 + Paillier
3. `SUBMISSION-STATUS.md` — gating items + Tier A path
4. `PROOF-CLAIMS.md` (this) — honest scope
5. `PARAMS.md` — secp256k1-specific parameters
6. `TEST-VECTORS.md` — KAT scope
7. `SECURITY.md` — threat model
8. Upstream: CCS '21 + ePrint 2021/060
9. Code: `cmp.go`, `keygen/`, `presign/`, `sign/`, `pkg/zk/*`

## §5 Cross-references

- `SUBMISSION-STATUS.md`
- `corona/PROOF-CLAIMS.md` — honest disclosure template
- `pulsar/PROOF-CLAIMS.md` — Tier A reference
