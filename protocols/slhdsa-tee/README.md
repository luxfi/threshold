# slhdsa-tee

Operator-controlled SLH-DSA threshold signing via TEE-gated master-seed
reconstruction.

## What this is

A composable Go package that produces FIPS 205 SLH-DSA signatures
gated on:

1. A verifiable hardware TEE attestation (AMD SEV-SNP, Intel TDX, NVIDIA NRAS)
   chain-validated by `github.com/luxfi/mpc/cc/attest`.
2. A KMS release-gate (`github.com/luxfi/mpc/pkg/kms.ReleaseGate`) that pins
   the worker's RIM digest + hardware fingerprint and binds a single-use
   challenge nonce per request.
3. An out-of-band human or programmatic approval signature
   (`github.com/luxfi/mpc/pkg/approval.ApprovalProvider`).
4. An HSM-resident wrap-key store (`github.com/luxfi/mpc/pkg/hsm.Provider`)
   so the master SLH-DSA seed lives sealed-at-rest and is only ever
   unwrapped inside the attested TEE.

Output is byte-identical to single-party FIPS 205 `SignDeterministic` on
the same `(seed-derived sk, msg, ctx)` tuple. Any verifier holding the
published MAGG-framed group public key validates with
`magnetar.VerifyBytes` — no awareness of the threshold or TEE substrate
is required.

## When to use this

- **M-Chain bridge custody**: an operator holds the bridge's signing key
  inside a SEV-SNP / TDX TEE. Per-redemption sign calls require an
  attestation envelope plus an executive approval. The master seed
  never leaves the HSM in plaintext outside the attested TEE context.
- **A-Chain confidential-compute oracle**: an oracle node produces
  SLH-DSA attestations over confidential model outputs. The output is
  gated on the worker's RIM matching a known-good measurement
  allowlist.

## When NOT to use this

- **Public-BFT consensus**: use the per-validator standalone
  `magnetar.ValidatorSign` path (canonical v0.5+). No DKG, no dealer,
  no aggregator-in-TCB.
- **Permissionless threshold custody**: use `magnetar.Combine`
  (THBS-SE, v0.1 reveal-and-aggregate) — no party ever holds the master
  seed, so there is no TCB to attest.
- **Test / dev with no TEE hardware available**: use
  `magnetar.GenerateKey` + `magnetar.Sign` directly.

## Decision matrix

| Use case | Primitive |
|----------|-----------|
| Public-BFT validator | `magnetar.ValidatorSign` (PRIMARY) |
| Permissionless N-of-N custody, no party holds seed | `magnetar.Combine` (THBS-SE) |
| Institutional custody with attested release | `slhdsa-tee.Signer.Sign` (THIS) |
| Single-party / dev | `magnetar.Sign` |

## Layering

```
caller (operator daemon, bridge node, custody orchestrator)
  └── slhdsatee.Signer.Sign(ctx, env, jobID, msg, signCtx)
        ├── approval.ApprovalProvider.ApproveIntent  (out-of-band gate)
        ├── kms.ReleaseGate.Issue / Release          (TEE-gated wrap key)
        │     └── cc/attest.Dispatch                  (vendor chain verify)
        ├── hsm.Provider.GetKey                       (wrapped seed at rest)
        ├── magnetar.KeyFromSeed → magnetar.Sign      (FIPS 205 emit)
        └── hsm.Provider.Sign                         (audit signature)
```

Each step is independently complete and replaceable.

## Threat model

- **Compromised operator binary outside TEE**: refused — no valid
  attestation possible.
- **Forged attestation envelope (chain-invalid)**: refused at
  `cc/attest.Dispatch` → `kms.ErrAttestationChain`.
- **Replay of an old sealed key**: refused — AAD binds (epoch, jobID,
  teePub, issuedNonce).
- **Coerced approver**: detectable in the receipt's audit signature
  trail.
- **Stolen master seed at rest**: protected by HSM root-of-trust (AWS
  KMS, Azure Key Vault, GCP Cloud KMS, YubiHSM, Zymbit, file with
  age-encryption).

## Example

```go
import (
    slhdsatee "github.com/luxfi/threshold/protocols/slhdsa-tee"
    magnetar "github.com/luxfi/magnetar/ref/go/pkg/magnetar"
    "github.com/luxfi/mpc/pkg/kms"
    "github.com/luxfi/mpc/pkg/hsm"
    "github.com/luxfi/mpc/pkg/approval"
)

policy := kms.NewReleasePolicyStrict([][32]byte{knownRIM}, [][32]byte{knownHW})
store := kms.NewMemoryNonceStore() // or DatabaseNonceStore in prod
gate, _ := kms.NewLocalReleaseGate(policy, store, rootKey)
hsmP, _ := hsm.NewAWSProvider(awsCfg)
appr, _ := approval.NewProvider("webauthn", webauthnCfg)

cfg := slhdsatee.Config{
    Mode:             magnetar.ModeM192s,
    RequiredRIM:      policy.RequiredRIM,
    AllowedHardware:  policy.AllowedHardware,
    RequireSEVSNP:    true,
    KMSKeyID:         "arn:aws:kms:us-east-1:...:key/...",
    WrappedSeedKeyID: "lux-custody-master-seed",
    ApprovalRequired: true,
    ApproverID:       "custody-ceo@org.example",
}
signer, _ := slhdsatee.New(gate, hsmP, appr, cfg)

env := &slhdsatee.Envelope{
    Kind:          attest.KindSEVSNP,
    EvidenceBytes: liveAttestationBytes,
    RIM:           knownRIM,
    Hardware:      knownHW,
    TEEPub:        workerTEEPub,
}
jobID, _ := slhdsatee.FreshJobID()
sig, receipt, err := signer.Sign(ctx, env, jobID, msg, nil)
```

## Dispatcher wiring

The `pkg/thresholdd` JSON-RPC dispatcher gains a `Sign_TEE` method on
the magnetar scheme that calls this package. The default `Sign` method
remains permissionless (per-validator standalone).
