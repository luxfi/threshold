// SPDX-License-Identifier: BSD-3-Clause

// Package slhdsatee implements operator-controlled SLH-DSA threshold
// signing via TEE-gated master-seed reconstruction.
//
// This is NOT a public-BFT primitive. Magnetar v0.5's per-validator
// standalone path (and v0.1 reveal-and-aggregate THBS-SE for delegated
// custody) is the canonical permissionless path; THIS package is the
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
//     (github.com/luxfi/mpc/pkg/hsm.Provider) so the master SLH-DSA
//     seed lives sealed-at-rest and is only ever unwrapped inside the
//     attested TEE.
//
// The sign call returns bytes byte-identical to single-party FIPS 205
// SLH-DSA SignDeterministic on (master_seed → KeyFromSeed → Sign(msg,
// ctx)). Any caller holding the published MAGG-framed group public key
// can verify with magnetar.VerifyBytes (or Verify) — no awareness of
// the threshold or TEE substrate is required.
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
//     refuses on chain-invalid; this package's Envelope ties the cc/attest
//     verifier into that contract.
//
// What this package is NOT:
//
//   - NOT a no-trusted-dealer DKG. The master seed is generated once
//     under TEE attestation; subsequent signs only release the wrapped
//     seed under the same attestation policy. A real DKG construction
//     for SLH-DSA is the magnetar package's THBS-SE family — see
//     magnetar/ref/go/pkg/magnetar/thbsse.go for the permissionless
//     primitive that produces a FIPS 205 byte-identical signature
//     without any party ever holding the master seed.
//
//   - NOT a substitute for magnetar.ValidatorSign or magnetar.Combine
//     on the public-BFT consensus surface. Use this ONLY when the
//     threat model permits "trusted custody with attested release"
//     (e.g. M-Chain bridge custody operator, A-Chain confidential
//     compute oracle).
//
// Wire compatibility: output is a magnetar.Signature (mode default
// ModeM192s) — the same wire form the dispatcher emits today. The
// SDK / verifier path is unchanged.
package slhdsatee
