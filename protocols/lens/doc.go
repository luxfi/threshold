// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package lens is the curve-based threshold-kernel — the classical
// analogue of Pulsar (lattice).
//
// Status: SHIPPING. The Lens kernel is implemented at
// github.com/luxfi/lens and the LSS adapter at
// threshold/protocols/lss/lss_lens.go. This package will hold the
// round-based wire wrapper when needed; for now, callers go directly
// through the LSS-Lens adapter (DynamicReshareLens).
//
// # The Pulsar / Lens symmetry
//
// Lux runs two parallel threshold-kernel families:
//
//	Pulsar (~/work/lux/pulsar)
//	  - PQ lattice threshold kernel
//	  - Module-LWE / R_q
//	  - Sign1/Sign2/Combine math forked byte-equal from upstream Ringtail
//	  - Pulsar replaces upstream's broken Feldman DKG and the
//	    trusted-dealer-per-epoch lifecycle
//
//	Lens (~/work/lux/lens)
//	  - Classical curve threshold kernel
//	  - Discrete-log over a prime-order group (Ed25519, secp256k1,
//	    Ristretto255)
//	  - Round 1 / Round 2 / Aggregate math implementing FROST per
//	    RFC 9591 (Komlo-Goldberg 2020)
//	  - Lens replaces the stub LSS-FROST integration with a proper
//	    curve-math kernel; carries the same key-era + VSR resharing
//	    lifecycle Pulsar carries
//
// Both kernels share the lifecycle invariant:
//
//	Genesis only:    proper distributed DKG (FROST DKG for Lens; Pedersen
//	                 DKG over R_q for Pulsar via pulsar/dkg2/),
//	                 OR trusted-dealer Bootstrap MPC ceremony.
//	Every epoch:     NEVER trusted dealer. VSR resharing under the
//	                 persistent GroupKey.
//	Reanchor:        rare governance event; fresh ceremony.
//
// # Layer separation
//
//	github.com/luxfi/lens                  (math kernel — SHIPPING)
//	github.com/luxfi/threshold/
//	  protocols/lens (this package)        (round-based wrapper — placeholder)
//	  protocols/lss/lss_lens.go            (LSS adapter — SHIPPING)
//	  protocols/frost/                     (upstream FROST primitives;
//	                                       reference, consumed by Lens)
//
// Note: "Lens Protocol" is a Web3/SocialFi project unrelated to this
// work. In docs and papers we say "Lux Lens" or "Lens threshold
// kernel" — never the bare phrase "Lens Protocol".
//
// # Vocabulary
//
//	Pulsar = lattice threshold kernel
//	Lens   = curve threshold kernel
//	LSS    = lifecycle / orchestration framework (Seesahai 2025)
//	BLS    = independent-validator aggregate lane (different shape;
//	         not threshold under one shared key)
//
// Lens is NOT the same as BLS aggregate. BLS aggregates signatures
// from independent validator keypairs; Lens is threshold under one
// shared curve group key. Quasar uses both: BLS Beams for fast
// classical aggregate finality, Lens (when adopted) for classical
// threshold control-plane / committee certs.
//
// # Acceptance criteria (locked, all passing)
//
// See threshold/protocols/lss/lss_lens_test.go for the canonical
// adapter tests:
//
//  1. Group public key preserved across resharing.
//  2. KeyEraID preserved across resharing.
//  3. Generation increments by one.
//  4. RollbackFrom = 0 on forward transition.
//  5. t_old != t_new works.
//  6. old set != new set works.
//  7. New shares produce a valid FROST signature under unchanged
//     group key (covers Ed25519 / secp256k1 / Ristretto255).
//  8. Pairwise material regenerated for new party set.
//  9. Rollback restores previous generation snapshot.
//  10. Activation cert format covers the chain-side circuit-breaker.
//
// Plus Lens-specific tests in github.com/luxfi/lens/{primitives, sign,
// reshare, dkg, keyera}/_test.go cover:
//
//   - RFC 9591-compatible FROST signing path on every shipped curve.
//   - Pedersen commitment verification over the selected curve group.
//   - Nonce / binding-factor handling matches FROST requirements.
//   - No hardcoded ChainKey / RID (LSS-FROST stub gap closed).
//
// # Cited works
//
//   - Komlo, Goldberg 2020. "FROST: Flexible Round-Optimized Schnorr
//     Threshold Signatures." SAC 2020.
//   - RFC 9591. "The Flexible Round-Optimized Schnorr Threshold
//     (FROST) Protocol for Two-Round Schnorr Signatures." 2024.
//   - HJKY97. Herzberg-Jakobsson-Jarecki-Krawczyk-Yung. "Proactive
//     Secret Sharing or: How to Cope With Perpetual Leakage."
//   - Desmedt-Jajodia 1997. "Redistributing Secret Shares to New
//     Access Structures."
//   - Wong-Wang-Wing 2002. "Verifiable Secret Redistribution for
//     Archive Systems."
//   - Seesahai 2025. "LSS MPC ECDSA: A Pragmatic Framework for
//     Dynamic and Resilient Threshold Signatures." (LSS framework)
package lens
