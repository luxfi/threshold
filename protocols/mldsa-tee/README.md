# mldsa-tee

Operator-controlled ML-DSA threshold signing via TEE-gated master-seed
reconstruction.

## What this is

Sibling of `protocols/slhdsa-tee` for the FIPS 204 (ML-DSA / Dilithium)
primitive. Output is byte-identical to single-party
`pulsar.SignDeterministic` on the same seed-derived `sk`.

## When to use

- Institutional custody of ML-DSA signing keys with HSM-resident wrap.
- IAM signing-as-a-service that requires attested release per operation.
- Bridge oracles whose signing key is governed by an executive approval flow.

## When NOT to use

- Permissionless threshold custody: use `pulsar.OrchestrateV03Sign`
  (v0.3 AlgebraicAggregate) — no party ever holds the master sk.
- Single-party / dev: use `pulsar.GenerateKey` + `pulsar.Sign`.

## Layering

```
caller
  └── mldsatee.Signer.Sign(ctx, env, jobID, msg, signCtx)
        ├── approval.ApprovalProvider.ApproveIntent
        ├── kms.ReleaseGate.Issue / Release
        │     └── cc/attest.Dispatch
        ├── hsm.Provider.GetKey
        ├── pulsar.KeyFromSeed → pulsar.Sign
        └── hsm.Provider.Sign (audit)
```

Each step is independently complete and replaceable. The default
permissionless path (`pulsar.OrchestrateV03Sign`) remains the
canonical surface; this TEE-extension is opt-in via the threshold
dispatcher's `Sign_TEE` method.
