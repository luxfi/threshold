// SPDX-License-Identifier: BSD-3-Clause

// Package mldsatee implements operator-controlled ML-DSA threshold
// signing via TEE-gated master-seed reconstruction.
//
// This is NOT a public-BFT primitive. Pulsar v0.3 AlgebraicAggregate
// is the canonical permissionless threshold path; THIS package is the
// institutional-custody-only extension that binds key release to:
//
//  1. a verifiable hardware TEE attestation (AMD SEV-SNP / Intel TDX /
//     NVIDIA NRAS) chain-validated by github.com/luxfi/mpc/cc/attest;
//  2. a KMS release-gate (github.com/luxfi/mpc/pkg/kms.ReleaseGate)
//     that pins the worker's RIM digest + hardware fingerprint and
//     binds a single-use challenge nonce per-request;
//  3. an out-of-band human / programmatic approval signature
//     (github.com/luxfi/mpc/pkg/approval.ApprovalProvider);
//  4. an HSM-resident wrap-key store
//     (github.com/luxfi/mpc/pkg/hsm.Provider) so the master ML-DSA
//     seed (32 bytes, FIPS 204) lives sealed-at-rest and is only
//     ever unwrapped inside the attested TEE.
//
// The sign call returns bytes byte-identical to single-party FIPS 204
// ML-DSA SignDeterministic on (master_seed → KeyFromSeed → Sign(msg,
// ctx)). Any caller holding the published PULG-framed group public
// key can verify with pulsar.VerifyBytes (or Verify) — no awareness
// of the threshold or TEE substrate is required.
//
// Threat model:
//
//   - Adversary controls the operator process (compromised binary,
//     malicious operator) outside the TEE. Without a valid attestation
//     that chains to the pinned vendor root AND a fresh approval that
//     matches the RIM/hardware policy, no sign is possible. The HSM
//     never releases the master seed in plaintext — only the AEAD
//     ciphertext sealed to the gate-issued ephemeral pubkey can leave
//     the gate.
//   - Adversary recovers an old sealed key. AAD binds (epoch, jobID,
//     teePub, issuedNonce); replay across epoch or jobID is refused.
//   - Adversary forges an attestation envelope whose Verify(nonce)
//     returns true but whose evidence does not chain to the vendor
//     root. ReleaseGate.Release calls CompositeAttestation.VerifyEvidence
//     which dispatches every blob through cc/attest.Dispatch and
//     refuses on chain-invalid.
//
// What this package is NOT:
//
//   - NOT a no-trusted-dealer DKG. The master seed is generated once
//     under TEE attestation; subsequent signs only release the wrapped
//     seed under the same attestation policy. The permissionless DKG
//     construction for ML-DSA is pulsar v1.0.23 AlgebraicAggregate —
//     see pulsar/ref/go/pkg/pulsar/threshold.go.
//
//   - NOT a substitute for pulsar.OrchestrateV03Sign on the public-BFT
//     surface. Use this ONLY when the threat model permits "trusted
//     custody with attested release" (e.g. M-Chain bridge custody,
//     A-Chain confidential compute oracle, IAM signing-as-a-service).
//
// Wire compatibility: output is a pulsar.Signature (mode default
// ModeP65) — the same wire form the dispatcher emits today. The SDK /
// verifier path is unchanged.
package mldsatee
