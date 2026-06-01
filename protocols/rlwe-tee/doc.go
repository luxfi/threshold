// SPDX-License-Identifier: BSD-3-Clause

// Package rlwetee implements operator-controlled Ring-LWE threshold
// signing via TEE-gated trusted-dealer-key reconstruction.
//
// This is NOT a public-BFT primitive. Corona v0.7.3 BootstrapPedersen
// is the canonical permissionless DKG path (no party ever holds the
// master); THIS package is the institutional-custody-only extension
// that binds key release to:
//
//  1. a verifiable hardware TEE attestation (AMD SEV-SNP / Intel TDX /
//     NVIDIA NRAS) chain-validated by github.com/luxfi/mpc/cc/attest;
//  2. a KMS release-gate (github.com/luxfi/mpc/pkg/kms.ReleaseGate)
//     that pins the worker's RIM digest + hardware fingerprint and
//     binds a single-use challenge nonce per-request;
//  3. an out-of-band human / programmatic approval signature
//     (github.com/luxfi/mpc/pkg/approval.ApprovalProvider);
//  4. an HSM-resident wrap-key store
//     (github.com/luxfi/mpc/pkg/hsm.Provider) so the master 32-byte
//     trusted-dealer key (sign.KeySize) lives sealed-at-rest and is
//     only ever unwrapped inside the attested TEE.
//
// Per-sign flow:
//
//  1. Verify attestation envelope chain validity + RIM + hardware
//     allowlist + approval.
//  2. Release the wrapped master trusted-dealer key from the HSM.
//  3. Inside the TEE: deterministically regenerate the n key shares
//     and the GroupKey by re-running corona.threshold.GenerateKeys
//     with the master key as PRNG seed.
//  4. Drive Round1 → Round2 → Finalize across all n parties in the
//     same TEE process. The resulting Signature is structurally
//     identical to a permissionless corona threshold signature on
//     the same message and group public key.
//  5. Zeroize the master key and per-party shares.
//
// Verification surface is corona.threshold.Verify(gk, msg, sig). Any
// caller holding the published GroupKey wire bytes can validate with
// corona.threshold.VerifyBytes — no awareness of the TEE substrate is
// required.
//
// Threat model:
//
//   - Adversary outside TEE: cannot produce a valid attestation, so
//     gate refuses release; no signing possible.
//   - Forged attestation: cc/attest chain refuses; ErrAttestationChain.
//   - Replay of old sealed key: AAD-binding (epoch, jobID, teePub,
//     issuedNonce) refuses cross-epoch / cross-job.
//
// What this package is NOT:
//
//   - NOT a substitute for corona.keyera.BootstrapPedersen on the
//     public-BFT surface. The Pedersen-DKG path (no trusted dealer)
//     is the canonical permissionless construction. Use rlwe-tee
//     ONLY when the threat model permits "trusted dealer inside an
//     attested TEE" (foundation HSM ceremonies, single-operator
//     custody).
//
//   - NOT a distributed protocol. All n parties run in the same
//     attested process; the network surface is exactly the
//     attestation envelope, the gate release request, and the
//     resulting wire-form signature.
package rlwetee
