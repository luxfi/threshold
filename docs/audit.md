# Security Audit and Threat Model

This document describes the security posture of the `luxfi/threshold` library:
the adversarial model each protocol is analyzed under, the tolerance
bounds that follow from the underlying proofs, the assumptions we rely on
(classical and post-quantum), deployment-level considerations, and the
current status of external audits.

It is the substantive response to [#5](https://github.com/luxfi/threshold/issues/5) and cross-references the HSM
guidance in [`hsm-integration.md`](./hsm-integration.md).

> **Bottom line.** Do not deploy this library to mainnet custodying
> user funds without performing — or commissioning — your own
> security review. The production-readiness badges in the README refer
> to test coverage, correctness testing, and internal review; they are
> **not** a substitute for an external cryptographic audit. An external
> audit has not yet been commissioned — see [Audit Status](#audit-status) below.

---

## 1. Threat Model

### 1.1 Parties and Corruptions

Each protocol is analyzed under a **static, malicious adversary** that
corrupts up to `t - 1` of the `n` signing parties (or, for Doerner's
two-party protocol, exactly one of the two parties). "Malicious" means
the adversary deviates arbitrarily from the protocol — it may forge
messages, equivocate, drop, reorder, or selectively withhold them.

The adversary is **rushing**: in each round it may wait to see every
honest party's message before deciding what its own corrupted parties
send.

**Not modelled:**

- **Adaptive corruption.** We assume the adversary chooses its
  corruption set before the protocol begins and does not learn new
  secrets mid-execution. Proactive share refresh (see LSS, and `Refresh`
  in CMP / FROST) mitigates this operationally by forcing an adaptive
  adversary to compromise enough shares within a single epoch.
- **Denial of service** from honest-majority party behaviour. An
  honest-majority failure is treated as an availability problem, not a
  security problem — signatures are not forgeable, but signing throughput
  is reduced.
- **Side channels on the host.** Constant-time arithmetic (via
  [`cronokirby/saferith`](https://github.com/cronokirby/saferith)) protects
  against timing and cache-timing side channels on the secret path, but
  the library does not defend against physical side channels (power
  analysis, EM) or against a compromised host OS.

### 1.2 Network Assumptions

The library operates over an **authenticated, confidential, partially
synchronous** channel abstraction supplied by the caller. Concretely:

- **Authentication and confidentiality** must be provided below the
  library — typically TLS with mutually-trusted certificates, or an
  authenticated gossip overlay such as `luxfi/mpc`'s ZAP transport.
- **Broadcast** is implemented via the primitive in
  [`docs/Broadcast.md`](./Broadcast.md): a two-round echo-then-agree
  broadcast that guarantees consistency over a point-to-point
  authenticated channel. Do **not** use a naive `send to all` as a
  broadcast in production — it does not prevent equivocation by a
  rushing adversary.
- **Liveness** assumes messages are eventually delivered. Under network
  partition the protocol stalls rather than completes unsafely.

The provided `internal/test.Network` is for tests only.

### 1.3 Randomness

Every party is assumed to have access to a reliable OS-level
cryptographically-secure random source (`crypto/rand.Reader`). A broken
RNG on any participating party breaks unforgeability. When running inside
a VM, ensure virtio-rng or equivalent is configured — do not rely on
a freshly-cloned VM's entropy pool.

---

## 2. Protocol-by-Protocol Security Notes

Each section below: what the protocol is, its original reference, the
tolerance bound that follows from the proof, and any caveats specific
to this implementation.

### 2.1 CMP — `protocols/cmp/`

**Reference.** Canetti, Gennaro, Goldfeder, Makriyannis, Peled,
_UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts_, CCS 2020
([eprint 2020/492](https://eprint.iacr.org/2020/492),
sometimes cited with the 2021 update as "CGGMP21", [eprint 2021/060](https://eprint.iacr.org/2021/060)).

**What it gives you.** UC-secure threshold ECDSA over `secp256k1`
with 4 online rounds and 7 presigning rounds. **Identifiable abort**
means an honest party can produce a publicly-verifiable proof of which
corrupted party caused an abort, as long as that party runs the
reference implementation.

**Tolerance bound.** `t <= n - 1` (dishonest-majority model). The
protocol tolerates `t - 1` malicious corruptions out of `n` signers.
Unforgeability and identifiable abort both hold up to this bound.

**Assumptions.**

- Hardness of ECDSA / DLP on `secp256k1`.
- Paillier encryption is IND-CPA (factoring-hard RSA moduli).
- The Strong RSA assumption (for Pedersen commitments / aux parameters).
- Random oracle model for Fiat–Shamir transforms.

**Implementation caveats.**

- The SSID hash is computed deterministically from the session parameters
  — if your wire serialization is non-canonical, two honest parties can
  derive distinct SSIDs and the protocol will fail safely at the next
  verification step. See [`docs/Threshold.md`](./Threshold.md) for the
  canonical form.
- **Identifiable abort is only identifiable against the reference
  implementation.** A malicious party running a modified implementation
  may produce an abort without publishing the attribution proof. In a
  regulated-custody setting, treat any abort as a possible malicious
  event until logs from every party have been reviewed.
- Paillier modulus generation uses `4κ`-bit safe primes
  (κ = 128, so 1024-bit primes, 2048-bit modulus). Keygen is latency-
  dominated by this step on first run.

### 2.2 FROST — `protocols/frost/`

**Reference.** Komlo, Goldberg, _FROST: Flexible Round-Optimized Schnorr
Threshold Signatures_, SAC 2020
([eprint 2020/852](https://eprint.iacr.org/2020/852)).
Security of the two-round variant is further analyzed in Crites, Komlo,
Maller, _Fully Adaptive Schnorr Threshold Signatures_
([eprint 2023/899](https://eprint.iacr.org/2023/899)).

**What it gives you.** Two-round (online) Schnorr threshold signatures,
EUF-CMA secure in the random-oracle model. Works on Ed25519, secp256k1,
and Ristretto255 (for SR25519). BIP-340 Taproot compatible — see
`pkg/taproot/` for the normalization rules we apply.

**Tolerance bound.** `t <= n` in the general setting; for standard
dishonest-majority Schnorr the usable bound is `t - 1` malicious out of
`n`. FROST uses committees for signing; the signing quorum must have
size `>= t`.

**Assumptions.**

- Hardness of discrete log on the underlying curve.
- Random oracle model for the hash function.
- One-more discrete-log (OMDL) assumption for the pre-processing (nonce)
  phase of the two-round variant.

**Implementation caveats.**

- This implementation targets the **committed nonce pair** variant. The
  earlier "FROST1" single-nonce variant has a known attack against
  adaptive adversaries (see [eprint 2023/899](https://eprint.iacr.org/2023/899)); we do not implement it.
- Key derivation via BIP-32-style chaining (see `config.DeriveChild`)
  preserves FROST security provided the chain code is distributed to
  all parties — do not derive child keys with a chain code the
  adversary can learn.
- The SR25519 variant uses Ristretto255; verification must account for
  the SR25519 serialization quirk (see
  `protocols/frost/frost_sr25519_test.go`).

### 2.3 LSS — `protocols/lss/`

**Reference.** Seesahai, _LSS MPC ECDSA: A Pragmatic Framework for
Dynamic and Resilient Threshold Signatures_, 2025
([`protocols/lss/README.md`](../protocols/lss/README.md)).

**What it gives you.** ECDSA threshold signing with explicit support for
**dynamic resharing** — adding or removing parties and changing the
threshold without reconstructing the master key. The `Reshare` protocol
rotates all shares; the on-chain public key and addresses are unchanged.

**Tolerance bound.** `t <= n - 1` for signing (dishonest majority, as
CMP). During a reshare, the **intersection** of the old and new
committees must contain at least `t_old` honest parties for the
re-randomization to be secure — otherwise the adversary can learn the
old secret and forge post-reshare signatures. Plan cohort changes
accordingly.

**Assumptions.** Same as CMP (the LSS implementation composes with CMP
under the hood — see `protocols/lss/lss_cmp.go`).

**Implementation caveats.**

- `rollback.go` exposes a generation-based rollback primitive. Rolling
  back past a reshare that was triggered by suspected compromise
  **re-enables** the compromised shares. Use rollback only for aborted
  or failed resharings, never as a response to compromise.
- The `dealer` subpackage supports an initial distribution from a single
  party; this is a trusted-dealer deployment and weakens the
  no-single-point-of-failure property. Production deployments should
  prefer distributed keygen.

### 2.4 Doerner (2-of-2 ECDSA) — `protocols/doerner/`

**Reference.** Doerner, Kondi, Lee, Shelat, _Secure Two-party Threshold
ECDSA from ECDSA Assumptions_, IEEE S&P 2018
([eprint 2018/499](https://eprint.iacr.org/2018/499)).

**What it gives you.** 2-of-2 threshold ECDSA optimized for the
two-party case — constant-time, ~5 ms signing, no Paillier. Designed
for wallet-plus-cosigner deployments.

**Tolerance bound.** The protocol is 2-of-2 only: both parties must be
honest for safety. It tolerates `0` malicious parties; one compromised
party means the adversary can forge (i.e., the protocol is a splitting
primitive, not a fault-tolerance primitive). **For `t-of-n` where `n > 2`, use CMP or LSS.**

**Assumptions.**

- Hardness of ECDSA / DLP on `secp256k1`.
- Oblivious transfer with simulation-based security (implemented via
  VOLE / Correlated OT in this repo).

**Implementation caveats.**

- The sender / receiver roles are asymmetric — the `ConfigSender` and
  `ConfigReceiver` are not interchangeable and must be matched correctly
  across sessions.
- Does not implement identifiable abort — a failed sign reveals
  only that one of the two parties misbehaved, not which.

### 2.5 Ringtail (Post-Quantum) — `protocols/ringtail/`

**Reference.** Ringtail wraps the implementation at
[`luxfi/ringtail`](https://github.com/luxfi/ringtail). The underlying
construction is a lattice-based two-round threshold signature in the
style of
[Gur, Katz, Silde, _Two-Round Threshold Lattice Signatures from Threshold Homomorphic Encryption_](https://eprint.iacr.org/2024/181), with
adaptations for the three-level security mode exposed here.

**What it gives you.** `(t, n)`-threshold signatures resistant to known
quantum attacks, selectable at 128 / 192 / 256-bit classical-equivalent
security.

**Tolerance bound.** `t <= n - 1` malicious in the standard model the
underlying construction targets. The Ringtail wrapper supports both key
generation and **share refresh** for proactive security — a quantum
adversary that compromises shares in one epoch cannot sign after the
next refresh without re-compromising.

**Assumptions.**

- **Module Learning With Errors (M-LWE)** and **Module Short Integer Solution (M-SIS)** in the lattice underlying the signature.
  These assumptions are currently believed to be hard against quantum
  attackers. **NIST selected ML-DSA (Dilithium) as its post-quantum
  signature standard under essentially the same family of assumptions**;
  cryptanalytic progress on M-LWE / M-SIS would affect both.
- Random oracle model for the Fiat–Shamir transform.

**Implementation caveats.**

- **Post-quantum does not mean audited.** The wrapper here has not been
  independently audited, and the reference construction has seen only a
  few years of scrutiny relative to ECDSA / Schnorr. Treat production
  deployment as experimental — specifically, do not rely on Ringtail as
  the **sole** signer for high-value custody today; compose it with a
  classical scheme for belt-and-braces (see `luxfi/mpc` triple-signing).
- Signatures are significantly larger than Schnorr (kilobytes vs 64
  bytes). This affects gas on chain and storage for archival.
- The security level parameter (128 / 192 / 256) controls the lattice
  dimension, not just the hash size. Changing it invalidates existing
  keys.

### 2.6 Unified Adapters — `protocols/adapters/`

The adapter layer (`cmp_adapter.go`, `frost_adapter.go`) is a plumbing
shim — it translates chain-specific transaction encodings and digest
rules into the generic signing API. It adds no cryptographic assumptions
of its own. **Correctness** of the per-chain digest and canonicalization
rules is critical (an incorrect digest rule produces valid signatures
over the wrong message). See the test suite under
`protocols/adapters/` and the chain-specific test files (e.g.,
`l2_chains_test.go` for Ethereum L2s).

---

## 3. BFT Tolerance Bounds — Quick Reference

| Protocol  | Mode                      | Safety Bound (malicious)         | Notes |
|-----------|---------------------------|----------------------------------|-------|
| CMP       | `t`-of-`n` with abort     | `t - 1` out of `n` (dishonest majority) | Identifiable abort vs reference impl only |
| FROST     | `t`-of-`n`                | `t - 1` out of `n`               | OMDL assumption for 2-round variant |
| LSS       | `t`-of-`n`, reshareable   | `t - 1` out of `n`; reshare requires `t_old` honest in intersection | Composes over CMP |
| Doerner   | 2-of-2                    | `0` (no fault tolerance)         | Both parties must be honest |
| Ringtail  | `t`-of-`n`                | `t - 1` out of `n`               | Post-quantum; assumption is M-LWE / M-SIS |

"BFT" in the context of threshold signing means unforgeability under
the stated bound. Liveness (the ability to produce a signature at all)
additionally requires `n - f >= t` honest, online parties, where `f` is
the number of offline or unresponsive parties.

### Why not `t < n/3`?

`t < n/3` is the bound for **Byzantine-agreement** style consensus
protocols that must simultaneously deliver agreement, validity, and
integrity in an asynchronous network. Threshold signing is a weaker
problem — safety requires only that fewer than `t` shares leak, which
permits the `t - 1` out of `n` bound above. If you compose threshold
signing with a BFT consensus layer (e.g., the `luxfi/consensus` triple-mode
finality), the overall system inherits the tightest bound of the
composed protocols, typically `t < n/3` of the consensus layer.

---

## 4. Post-Quantum Assumptions

- **Classical protocols** in this repo (CMP, FROST, LSS, Doerner) rely on
  ECDSA / DLP / RSA / Paillier hardness. **None of these survive a
  cryptographically relevant quantum computer.** A Shor-capable adversary
  can break any ECDSA or Schnorr signature and recover every private
  key ever used.
- **Ringtail** targets M-LWE / M-SIS hardness. Current cryptanalysis is
  consistent with the stated security levels, but post-quantum lattice
  cryptography is younger than elliptic-curve cryptography by decades;
  treat deployed parameters as "best current guess" rather than as
  settled.
- **Hybrid mode.** For long-lived custody or regulatory "crypto-agile"
  requirements, deploy a composition of a classical scheme (CMP / FROST)
  and Ringtail, accepting the signature of a transaction only when
  **both** verify. `luxfi/mpc`'s triple-signing arrangement (BLS +
  Ringtail + ML-DSA) is one such composition.
- **Migration path.** Plan for **in-place share migration**: generate
  Ringtail shares for the same validator set, begin dual-signing while
  still honoring classical signatures, cut over once an agreed-upon
  migration deadline has passed. Do not rotate public keys unless the
  downstream chain semantics require it.

---

## 5. Deployment Considerations

The library itself is one layer of a custody stack. These deployment-
level controls are outside the protocol's security proofs but inside the
**operator's** responsibility.

- **Key-share storage.** Shares must be encrypted at rest. `luxfi/mpc`
  encrypts each share with AES-256-GCM where the encryption key is
  resolved from an HSM provider at startup — see
  [`hsm-integration.md`](./hsm-integration.md) for the four supported
  provider integrations. A share leaked in plaintext from any party
  reduces the tolerance bound by one.
- **Key rotation / share refresh.** All of CMP, FROST, LSS, and Ringtail
  support share refresh — rotating shares without changing the public
  key. Run refresh on a regular cadence (quarterly is a common starting
  point) to limit the time window of adaptive compromise. After any
  suspected compromise, refresh immediately onto a **different cohort**
  that excludes the suspected party.
- **HSM integration.** In this library "HSM compatible" means the share
  **wire format** is opaque bytes that an HSM can store. The MPC
  computation itself does **not** run inside the HSM enclave — the share
  leaves the HSM, is used in process memory, and the result is stored
  back. For enclave-grade runtime isolation (AWS Nitro Enclaves, SGX),
  see [`hsm-integration.md`](./hsm-integration.md).
- **Observability and audit.** Every keygen, sign, and reshare should be
  emitted as an auditable structured-log event with the session ID,
  participant IDs, and result — but never the share material. Ship these
  logs off-host with tamper-evident retention.
- **Secure channels.** Do **not** use the `internal/test.Network`
  implementation in production. Production deployments must provide a
  mutually-authenticated, confidential transport. `luxfi/mpc`'s ZAP
  consensus transport is one such implementation.
- **Broadcast primitive.** When using CMP, LSS, or Ringtail, ensure your
  transport offers — or wraps — an echo-then-agree broadcast (see
  [`docs/Broadcast.md`](./Broadcast.md)). A naive fan-out does not
  prevent equivocation.

See [`hsm-integration.md`](./hsm-integration.md) for concrete
walkthroughs on AWS CloudHSM, Azure Key Vault, GCP Cloud HSM, and
Zymbit SCM.

---

## 6. Audit Status

| Component                                   | Status                                    |
| ------------------------------------------- | ----------------------------------------- |
| External third-party audit of this library  | ❌ Not yet commissioned                    |
| Internal review                             | ✅ Ongoing — tracked in this repo          |
| Upstream primitive audits                   | ✅ See [Upstream audits](#upstream-audits) |
| Responsible-disclosure process              | ✅ `security@lux.network`                  |

An external audit has not yet been commissioned. The production-readiness
badges in the README refer to test coverage, correctness testing, and
internal review — they are not a substitute for an external audit.

### Upstream Audits

Several building blocks are taken from — or closely track — implementations
that have themselves been audited. Those audits cover the primitive,
not its use in this library:

- **secp256k1 curve operations** — `decred/dcrd/dcrec/secp256k1/v4`, audited by the Decred project.
- **Paillier encryption and associated ZK proofs** — adapted from `taurushq-io/multi-party-sig`, following the CGGMP20 specification.
- **Ed25519 / Edwards operations** — `filippo.io/edwards25519`.
- **BLAKE3** — `lukechampine.com/blake3`.

If you are depending on one of these primitives in isolation, consult
the upstream audit directly.

### Responsible Disclosure

Report vulnerabilities privately to **`security@lux.network`**. Please
do **not** open a public issue for suspected security bugs. We will
acknowledge receipt within 72 hours and aim to confirm or reject the
report within 10 business days.

### Audit Log

External audits will be listed here once completed.

| Date | Auditor | Scope | Report |
| ---- | ------- | ----- | ------ |
| —    | —       | —     | —      |

---

## 7. Further Reading

- [`docs/Threshold.md`](./Threshold.md) — CMP implementation adaptations and the SSID hash spec.
- [`docs/FROST.md`](./FROST.md) — FROST rounds and serialization.
- [`docs/Broadcast.md`](./Broadcast.md) — the echo-then-agree broadcast primitive.
- [`docs/hsm-integration.md`](./hsm-integration.md) — HSM / KMS integration walkthroughs.
- [`protocols/lss/README.md`](../protocols/lss/README.md) — LSS protocol paper and reshare flow.
