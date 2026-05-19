# SECURITY — CGGMP21 (Lux Profile)

> Threat model + responsible-disclosure policy for the Lux CGGMP21
> profile.

## §1 Threat model

### 1.1 What CGGMP21 protects against

- **Up to `t-1` malicious or compromised signers**: cannot forge a
  signature without honest cooperation.
- **Adaptive corruption**: CCS '21 §3 covers static-adversary; the
  paper's §7 proactive-refresh extends to long-term adaptive
  corruption (provided refresh runs faster than the corruption
  budget exhausts).
- **Identifiable abort**: misbehaving signers detected via ZK
  subprotocol verification + round-N share verification.
- **Network partition / equivocation**: identifiable abort applies.
- **UC composition**: CCS '21 proves CGGMP21 secure under UC, so
  composing with other protocols (e.g., the LSS resharing wrapper)
  preserves security.

### 1.2 What CGGMP21 does NOT protect against

- **`t` or more colluding signers**: trivially can forge.
- **Compromised Paillier moduli**: a malicious party-N who generates
  a non-Blum-prime modulus could exploit the ZK subprotocols.
  Mitigation: biprime testing at keygen (`pkg/paillier`) — but see
  `SUBMISSION-STATUS.md §3.3` for the audit gating item.
- **Compromise of `crypto/secp256k1` underlying primitive**: out of
  scope for this protocol layer.
- **Side-channel attacks on Paillier exponentiation**: delegated to
  `pkg/paillier`. Not separately measured at the threshold layer.
- **Quantum adversary**: CGGMP21 is classical-only. PQ analogues are
  Pulsar (M-LWE), Corona (R-LWE).

## §2 Security argument

The Lux CGGMP21 profile inherits security from:

- **CCS '21 / ePrint 2021/060** — UC-secure, proactively secure,
  identifiable-abort.
- **secp256k1 DLog hardness** — underlying ECDSA security.
- **Paillier semantic security** — underlying MtA conversion.

Lux profile deltas (pinned curve, Paillier modulus size 2048,
transcript-binding tag) are conservative and do NOT modify the
security argument.

## §3 Known operational risks

| Risk | Mitigation |
|---|---|
| Insecure Paillier-modulus storage | Use `luxfi/kms` for custody |
| Replay across sessions | Session-ID is bound into transcript hash |
| Validator-set rotation without refresh | LSS-CMP adapter mandates resharing on validator-set delta |
| Presignature reuse | Each presignature is single-use; reuse detected by signing-round logic |
| Paillier modulus brute-force | 2048-bit modulus matches CCS '21 recommendation |

## §4 Responsible disclosure

Security issues should be reported to `security@lux.network`. See
`luxfi/threshold/SECURITY.md` (repo-level) for the umbrella policy.

DO NOT file security-sensitive issues in the public GitHub tracker.

## §5 Audit history

| Date | Auditor | Scope | Result |
|---|---|---|---|
| (none yet) | — | — | independent cryptographer review is a Tier B → A gate (SUBMISSION-STATUS.md §3.8) |

## §6 Upstream security tracking

- CCS '21 paper has been peer-reviewed.
- Subsequent CGGMP21-variant work (e.g., Doerner-Kondi-Lee-Shelat
  2023 for 1-round signing, GG20 simplifications) is tracked but
  NOT deployed in Lux profile v1; future LPs may add them.

## §7 Cross-references

- `PROOF-CLAIMS.md` §2 — non-claims
- `SUBMISSION-STATUS.md` §3.3 — Paillier audit gate
- `SUBMISSION-STATUS.md` §3.8 — cryptographer review gate
