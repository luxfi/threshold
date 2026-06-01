# rlwe-tee

Operator-controlled Ring-LWE threshold signing via TEE-gated
trusted-dealer-key reconstruction.

## What this is

Sibling of `protocols/slhdsa-tee` and `protocols/mldsa-tee` for the
corona Ring-LWE primitive. The master trusted-dealer key (32 bytes)
lives sealed-at-rest in the HSM; per sign call the TEE attestation
authorizes release, then the dealer's `GenerateKeys` + the n-party
Round1/Round2/Finalize all run inside the attested process. The
resulting `corona.threshold.Signature` is structurally identical to
a permissionless corona threshold signature on the same `(GroupKey,
message)`.

## When to use

- Foundation HSM ceremonies that need a single-operator dealer with
  attested release.
- Bridge custody operators that hold a corona PQ threshold signing
  key and require executive approval per signature.

## When NOT to use

- Permissionless threshold custody: use
  `corona.keyera.BootstrapPedersen` — no party ever holds the master
  trusted-dealer key.
- Single-operator dev: use `corona.threshold.GenerateKeys` directly.

## Layering

```
caller
  └── rlwetee.Signer.Sign(ctx, env, jobID, msg)
        ├── approval.ApprovalProvider.ApproveIntent
        ├── kms.ReleaseGate.Issue / Release
        │     └── cc/attest.Dispatch
        ├── hsm.Provider.GetKey
        ├── corona.threshold.GenerateKeys → Round1 → Round2 → Finalize
        └── hsm.Provider.Sign (audit)
```

## Compatibility

Wire output is `corona.threshold.Signature.MarshalBinary`. Verifiers
holding the published GroupKey bytes validate via
`corona.threshold.VerifyBytes(gkBytes, msg, sigBytes)` — no
awareness of the TEE substrate required.
