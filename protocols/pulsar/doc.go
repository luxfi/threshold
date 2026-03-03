// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package pulsar is the Quasar PQ-threshold lane — Lux's production
// evolution of the Ringtail lattice threshold signature scheme.
//
// # This package owns the round-based signing and verification wrappers,
// # NOT the dynamic-resharing lifecycle.
//
// Lifecycle orchestration (Generation tracking, RollbackManager,
// GenerationSnapshot history, Bootstrap Dealer / Signature Coordinator
// roles, live-resharing orchestration) lives in
// github.com/luxfi/threshold/protocols/lss — the universal Lux dynamic
// threshold lifecycle framework, paper-backed by Seesahai 2025.
//
// The LSS-Pulsar adapter at threshold/protocols/lss/lss_pulsar.go wires
// LSS lifecycle calls into Pulsar lattice share operations. Use that
// for production resharing. This package is the round/signing wrapper
// only.
//
// Pulsar is named for the cosmic object that maps the design invariant:
//
//	Persistent body  → GroupKey, A, hidden master secret s
//	Rotating beam    → epoch share distribution
//	Observed pulse   → threshold certificate emitted periodically
//
// Pulsars rotate on a fixed period; the body persists, only the beam
// direction changes. That is exactly what proactive resharing does:
// the GroupKey persists across epochs within a key era; only the share
// distribution rotates. The certificate emitted over a Quasar bundle is
// the "pulse" — a compact post-quantum threshold signature.
//
// # Vocabulary stack
//
// Pulsar fits into the broader Quasar consensus vocabulary as the PQ
// threshold finality lane. The full stack:
//
//	Photon   — individual validator vote / attestation
//	Beam     — fast classical aggregate (BLS)
//	Pulsar   — lattice threshold engine (this package)
//	Pulse    — one Pulsar threshold certificate emitted over a bundle
//	ML-DSA   — PQ individual accountability lane (cert-set, not aggregate)
//	Horizon  — Quasar-level finality boundary that combines all lanes
//	Quasar   — full leaderless consensus protocol
//
// Quasar reaches a post-quantum event horizon by collecting Pulsar
// threshold certificates, BLS beams, and ML-DSA attestations.
//
// # Lane composition
//
//	BLS:    each validator has its OWN keypair (independent)
//	ML-DSA: each validator has its OWN keypair (independent)
//	Pulsar: each validator holds a SHARE of one group key (threshold)
//
// The threshold property is the only reason to use Pulsar over per-
// validator Ringtail/ML-DSA: a Pulsar certificate is O(1) in the
// number of signers (compact PQ threshold), where ML-DSA is O(n) raw
// or O(1) under a Z-Chain Groth16 rollup.
//
// # Relation to protocols/ringtail
//
// protocols/ringtail/ wraps the upstream github.com/luxfi/ringtail
// (academic POC). It inherits two known issues:
//
//   - DKG path uses Feldman commits without MLWE noise — recoverable
//     via pseudoinverse (see luxcpp/crypto/pulsar/RED-DKG-REVIEW.md).
//   - Trusted-dealer-per-epoch model: every epoch rotation generates
//     a fresh GroupKey, which requires a new trust event each epoch
//     — wrong shape for permissionless validator sets.
//
// protocols/pulsar/ supersedes protocols/ringtail/ with:
//
//   - Corrected lattice kernel from github.com/luxfi/pulsar.
//   - Pedersen DKG over R_q (research path, dkg2/) for Reanchor.
//   - Trusted-setup once per key era, then Verifiable Secret Resharing
//     for every subsequent epoch — preserves GroupKey, no trusted
//     dealer needed for routine rotations.
//   - Activation certificate as the chain-level circuit breaker.
//   - Full key-era lifecycle: Bootstrap → Reshare* → Reanchor.
//
// protocols/ringtail/ should be marked deprecated; protocols/quasar/
// should switch to consuming protocols/pulsar/ for the lattice lane.
//
// # Layer separation
//
//	github.com/luxfi/pulsar (math kernel)
//	  ├── primitives, sign, threshold, reshare, dkg2, keyera
//	  └── single-process API; deterministic; KAT-replayable
//
//	github.com/luxfi/threshold/protocols/pulsar (this package)
//	  ├── round-based wrappers using internal/round/Session
//	  ├── party.ID, pool.Pool conventions
//	  └── distributed protocol entrypoints (StartFunc)
//
// # Round-based protocol structure (LSS pattern)
//
// The 3-round structure used by protocols/lss/reshare/ is the right
// shape for Pulsar's RefreshSameSet and ReshareToNewSet protocols:
//
//	Round 1: each old/participating party generates polynomial,
//	         broadcasts commitments + chain key.
//	Round 2: old parties privately deliver share evaluations to new
//	         parties; new parties verify against commitments.
//	Round 3: new parties combine into final shares; old parties may
//	         be removed.
//
// The activation certificate is a separate sign protocol (single round
// with the new committee) that runs after the resharing round 3
// completes. The chain admits the new EpochShareState only when the
// activation cert verifies under the unchanged GroupKey.
//
// LSS uses additive sharing on an elliptic curve (commits are g^s).
// Pulsar uses Pedersen-style commitments on the lattice ring R_q
// (commits are A·NTT(s) + B·NTT(r)). The protocol shape is identical;
// only the commitment math differs.
//
// # Domain-separated message prefixes
//
// All signatures produced under Pulsar's GroupKey carry a distinct
// version-tagged prefix. No shared prefix between any two:
//
//	QUASAR-PHOTON-VOTE-v1       — individual validator vote
//	QUASAR-BEAM-BLS-v1          — BLS aggregate certificate
//	QUASAR-MLDSA-ATTEST-v1      — ML-DSA attestation set
//	QUASAR-PULSAR-BUNDLE-v1     — Pulsar pulse over a bundle
//	QUASAR-PULSAR-SIGN1-v1      — Pulsar Round 1 message
//	QUASAR-PULSAR-SIGN2-v1      — Pulsar Round 2 message
//	QUASAR-PULSAR-COMBINE-v1    — Pulsar finalize transcript
//	QUASAR-PULSAR-REFRESH-v1    — Refresh activation cert
//	QUASAR-PULSAR-RESHARE-v1    — Reshare activation cert
//	QUASAR-PULSAR-ACTIVATE-v1   — generic activation message
//	QUASAR-PULSAR-REANCHOR-v1   — Reanchor authorization (governance)
//
// The activation message canonical bytes bind:
//
//	chain_id, network_id, key_era_id, group_id,
//	old_epoch, new_epoch,
//	old_validator_set_hash, new_validator_set_hash,
//	old_threshold, new_threshold,
//	group_public_key_hash,
//	reshare_transcript_hash,
//	pairwise_material_commitment_hash,
//	implementation_version
//
// The last two fields are essential for cross-language byte-identical
// KAT replay: pairwise_material_commitment binds the new committee's
// pairwise PRF/MAC derivation to a specific transcript moment;
// implementation_version distinguishes Go and C++ ports during
// development and pins the canonical byte format.
//
// # Quasar HorizonCertificate
//
// The composition Quasar emits at finality combines all lanes:
//
//	type HorizonCertificate struct {
//	    Beam   bls.AggregateCertificate
//	    MLDSA  mldsa.CertificateSet
//	    Pulsar pulsar.Certificate
//
//	    KeyEraID    pulsar.KeyEraID
//	    GroupID     pulsar.GroupID
//	    BundleRoot  ids.ID
//	}
//
// Verification order:
//
//	1. Verify domain separation and transcript binding.
//	2. Verify BLS Beam.
//	3. Verify ML-DSA attestation set against signer bitmap.
//	4. Verify Pulsar pulse under the active KeyEra/GroupKey.
//	5. Verify signer-set and validator-set hashes match epoch state.
//	6. Verify bundle root / block root linkage.
//
// # See also
//
//	github.com/luxfi/pulsar              — math kernel
//	github.com/luxfi/pulsar/DESIGN.md    — design source of truth
//	luxcpp/crypto/pulsar/                — byte-equal C++ port
//	protocols/quasar/                    — Quasar consensus orchestration
//	protocols/lss/reshare/               — round-based ECDSA reshare reference
package pulsar
