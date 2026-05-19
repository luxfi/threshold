# SECURITY — Threshold BLS (Lux profile)

> Threat model + responsible-disclosure policy for the threshold-BLS
> package at `github.com/luxfi/threshold/protocols/bls`.

## §1 Reporting vulnerabilities

Report cryptographic or implementation vulnerabilities privately to
**security@lux.network** — encrypted with the team key at
`https://lux.network/security/key.asc`. Public disclosure happens
after a fix lands and downstream consumers have had a 14-day private
window.

The disclosure timeline mirrors the Lux ecosystem default (T+5 ack,
T+30 fix, T+44 public; faster for critical findings, slower for
research-level findings requiring spec consultation).

## §2 Threat model

### §2.1 Adversary capabilities

- Static corruption of at most `t − 1` parties.
- Rushing Byzantine adversary among the corrupted set.
- Synchronous network with bounded message delivery.
- Computational adversary bounded by `co-CDH` hardness over
  BLS12-381 and random-oracle abstraction over the IETF
  `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_` hash-to-curve.

### §2.2 What is in-scope

- **Threshold-protocol soundness**: forgery, key-recovery, share-
  extraction, rogue-key, ID-collision in the polynomial evaluation
  field.
- **Constant-time violations** in threshold-layer paths that touch a
  secret share or a Lagrange-coefficient computation. (Single-party
  BLS CT is `luxfi/crypto/bls`'s problem; this scope covers the
  delta the threshold layer adds.)
- **Spec ambiguity** that leads to an exploitable verifier behaviour
  or non-byte-equal output across implementations.
- **Trusted-dealer keygen failures**: master secret not properly
  derived from CSPRNG, master secret leaked through error paths,
  verification keys inconsistent with shares.
- **Party-ID encoding bugs**: `party.ID(i).Scalar(F_r) == 0`
  silently producing a share equal to the master secret (see
  `SPEC.md` §4.2 / `PROOF-CLAIMS.md` §3.7).
- **Combine-path bugs**: incorrect Lagrange-coefficient computation,
  wrong polynomial degree, incorrect G2 scalar-mul.
- **API misuse vectors**: callers passing more than `t` shares
  (currently silently truncated), passing fewer than `t` shares
  (returns error), passing shares from different keygen runs
  (silently produces an invalid aggregate that fails verification).
- **KAT mismatches** between this Go reference and a future C++ port
  at `~/work/luxcpp/crypto/bls/threshold/`.

### §2.3 What is NOT in-scope

- **Single-party BLS bugs** in `luxfi/crypto/bls` or upstream
  `cloudflare/circl` — file there.
- **DKG soundness** — current implementation uses a trusted dealer;
  there is no DKG to attack. (Once Pedersen-DKG over `F_r` lands
  per `SUBMISSION-STATUS.md` §3.1, this scope will extend.)
- **Post-quantum hardness** — BLS is classically secure only. PQ
  replacements live at `~/work/lux/pulsar/` (M-LWE) and
  `~/work/lux/corona/` (R-LWE). Filing PQ findings against
  threshold-BLS is out of scope.
- **Application-level access control** — caller policy on when /
  who / what to sign is outside the threshold protocol.
- **Operator-level secret-share storage** — see future
  `DEPLOYMENT-RUNBOOK.md` for operator-facing guidance; this
  package does not enforce storage hygiene.
- **Performance / efficiency complaints** — file an issue.

## §3 Inherited security assumptions

Threshold-BLS inherits the following from upstream:

| Assumption | Source | Notes |
|---|---|---|
| `co-CDH` hardness over BLS12-381 | Boneh-Lynn-Shacham 2001 | Classical-secure only |
| Random-oracle modeling of hash-to-curve | IETF `draft-irtf-cfrg-bls-signature-05` §4.2.2 | Standard ROM assumption |
| Subgroup-check enforcement on G1 and G2 inputs | `cloudflare/circl` BLS12-381 | Must be enforced by `luxfi/crypto/bls` |
| Correct ciphersuite tag | `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_` | Pinned by `luxfi/crypto/bls.Sign`; threshold layer does not override |
| Constant-time scalar-mul on G2 | `cloudflare/circl` | Inherited; threshold layer relies on it |

If any of the above is found to be violated upstream, the threshold-
BLS path is affected. File upstream, not here.

## §4 Lux-specific deltas (threshold-layer)

The threshold layer adds the following surface area beyond
single-party BLS — these are the **new** attack vectors:

### §4.1 Party-ID validity gate

`SPEC.md` §4.2 documents that `party.ID(i).Scalar(F_r) ≠ 0` is a
must-not. The current implementation does NOT validate this. A
caller using arbitrary string IDs has a probability-1/r case where
the ID maps to zero and the share equals the master secret.

**Mitigation in deployment**: callers should constrain party IDs to
small bounded integers or hashed identifiers that explicitly avoid
the zero case. A `Config.Validate()` gate is on the Tier-A roadmap.

### §4.2 Polynomial-degree convention

The implementation uses degree `t − 1`. A reader or external
implementer that uses degree `t` will produce shares that
under-reconstruct (need `t + 1` to recover the secret) — this is a
**silent** interop failure: signatures aggregated under
degree-`t − 1` shares will not verify against signatures produced
under degree-`t` shares for the same `(t, n, master)`.

The KAT manifest, once it lands (`SUBMISSION-STATUS.md` §3.2), will
gate against this.

### §4.3 Lagrange-combine at fixed evaluation point

The combine evaluates Lagrange coefficients at `x = 0`. Using any
other evaluation point will compute a different combined signature
that does not byte-match the single-party comparator.

### §4.4 Rogue-key surface

See `PROOF-CLAIMS.md` §3.6. Under the current trusted-dealer flow
this is closed by construction. Under a future DKG it must be
re-opened and re-closed via PoP or polynomial-commitment binding.

### §4.5 Per-share verification responsibility

`Config.VerifyPartialSignature` exists but is **not** called inside
`AggregateSignatures`. A malicious party can submit a partial
signature on a different message; the combine will produce an
aggregate that fails final verification but does NOT identify the
offending party.

**Mitigation in deployment**: callers (e.g., the `pkg/thresholdd/`
dispatcher) should verify every partial signature before invoking
`AggregateSignatures`.

## §5 CVE assignment

Threshold-BLS maintainers will request CVEs for any in-scope
vulnerability prior to public disclosure. CVE numbers are embedded
in the `luxfi/threshold` release-tag commit message.

## §6 Coordinated disclosure with siblings

The classical threshold family (`bls`, `frost`, `cmp`) shares the
same security mailing list. A vulnerability affecting multiple
protocols (e.g., a flaw in the shared `pkg/math/polynomial` or
`pkg/party` surface) will be disclosed across all affected
packages simultaneously.

PQ siblings (`luxfi/pulsar`, `luxfi/corona`) have separate
mailing lists; cross-family findings (e.g., a hybrid-construction
binding flaw) are coordinated bilaterally.

## §7 References

- Boldyreva 2003 — threshold-BLS security argument.
- Boneh-Lynn-Shacham 2001 — BLS single-party security.
- IETF `draft-irtf-cfrg-bls-signature-05` — ciphersuite + verifier.
- `luxfi/crypto/bls` — single-party primitive.
- `SPEC.md` — protocol surface.
- `PROOF-CLAIMS.md` §3 — what is NOT proved.
- `SUBMISSION-STATUS.md` §3 — Tier-A gates.

---

**Document metadata**

- Name: `SECURITY.md`
- Version: v0.1 (initial submission-package scaffolding)
- Date: 2026-05-18
