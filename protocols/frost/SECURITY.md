# SECURITY — FROST (Lux Profile)

> Threat model + responsible-disclosure policy for the Lux FROST
> profile.

## §1 Threat model

### 1.1 What FROST protects against

- **Up to `t-1` malicious or compromised signers**: cannot forge a
  signature without honest cooperation.
- **Network partition / equivocation**: identifiable-abort
  (Komlo-Goldberg §5) lets honest parties blame misbehaving signers
  via round-2 share verification.
- **Long-term-key compromise of less than `t` parties**: no
  signature leakage; affected parties can be removed via LSS
  dynamic resharing (`protocols/lss/lss_frost.go`).

### 1.2 What FROST does NOT protect against

- **`t` or more colluding signers**: trivially can forge.
- **Compromise of the group public key's discrete-log**: not
  achievable today; pinned ciphersuites use Ed25519 and secp256k1
  with standard hardness.
- **Side-channel attacks on the underlying scalar arithmetic**:
  delegated to `luxfi/crypto/curve25519` and `luxfi/crypto/secp256k1`.
  Their CT posture is the relevant inheritance; FROST's threshold
  layer adds no new side-channel surface in principle but has not
  been measured (see `PROOF-CLAIMS.md §2.3`).
- **Quantum adversary**: FROST is classical-only. PQ-equivalent
  threshold schemes are Pulsar (M-LWE) and Corona (R-LWE).

## §2 Security argument

The Lux FROST profile inherits security from:

- **Komlo-Goldberg (SAC 2020 / ePrint 2020/852)** — the construction
  itself: unforgeability under DLog, identifiable abort.
- **IETF CFRG `draft-irtf-cfrg-frost`** — wire-format and ciphersuite
  normative reference.
- **The underlying ciphersuite hardness** — Ed25519's
  edwards25519 DLog, secp256k1's DLog.

The Lux profile's deltas (transcript-binding tags, party-id ordering,
threshold range bounds) do NOT modify the security argument; they
are conservative additions.

## §3 Known operational risks

| Risk | Mitigation |
|---|---|
| Key-share leak via insecure storage | Use `luxfi/kms` for share custody |
| Replay across ciphersuites | Lux profile binds via domain-separated transcript tags (see SPEC.md §3.3) |
| Replay across sessions | Session-ID is bound into the transcript hash |
| Validator-set rotation without resharing | LSS-FROST adapter mandates resharing on validator-set delta |

## §4 Responsible disclosure

Security issues in the Lux FROST profile should be reported to:

- **`security@lux.network`** — primary contact
- See `luxfi/threshold/SECURITY.md` (repo-level) for the umbrella policy

DO NOT file security-sensitive issues in the public GitHub tracker.

## §5 Audit history

| Date | Auditor | Scope | Result |
|---|---|---|---|
| (none yet) | — | — | independent cryptographer review is a Tier B → A gate (see SUBMISSION-STATUS.md §3.6) |

## §6 Upstream security tracking

- Komlo-Goldberg 2020 has been peer-reviewed and is the basis for
  the CFRG draft.
- The CFRG draft tracks community review; issues filed against the
  draft propagate to Lux profile updates.
- Subscribe to <https://datatracker.ietf.org/wg/cfrg/about/> for
  upstream notices.

## §7 Cross-references

- `PROOF-CLAIMS.md` §2.3 — CT non-claims
- `PROOF-CLAIMS.md` §2.5 — Lux-delta security analysis status
- `SUBMISSION-STATUS.md` §3.4 — identifiable-abort attribution gate
- `SUBMISSION-STATUS.md` §3.6 — independent cryptographer review gate
