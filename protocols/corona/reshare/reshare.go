// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package reshare re-exports github.com/luxfi/corona/reshare through
// the threshold/protocols/corona alias surface. Downstream consumers
// (luxfi/consensus) target this import path so the consensus engine
// does not depend directly on the corona module.
//
// The activation circuit-breaker (VerifyActivation + ActivationCert)
// is the chain-level gate that admits a new committee only when the
// new shares can threshold-sign under the unchanged GroupKey.
package reshare

import (
	"github.com/luxfi/corona/hash"
	"github.com/luxfi/corona/reshare"
)

// HashSuite is the hash-family identifier the activation transcript
// binds to. Aliased from the corona/hash package so callers do not
// import that package directly. Passing nil resolves to the production
// default (Corona-SHA3).
type HashSuite = hash.HashSuite

// Activation-cert types and the chain-level circuit-breaker.
type (
	// ActivationMessage is the canonical message the new committee
	// threshold-signs to authorise the share-set transition. Its
	// SignableBytes binds chain_id / network_id / key_era_id / group_id
	// / old+new epoch numbers / old+new validator-set hashes /
	// old+new threshold / group_public_key_hash / transcript hashes.
	ActivationMessage = reshare.ActivationMessage

	// ReshareTranscript is the public exchange transcript for the
	// reshare ceremony. The activation message's transcript-hash
	// field commits to this.
	ReshareTranscript = reshare.ReshareTranscript

	// ActivationCert is the threshold-signed activation message that
	// VerifyActivation consults. The cert is admissible only when its
	// embedded signature verifies under the unchanged GroupKey.
	ActivationCert = reshare.ActivationCert

	// TranscriptInputs is the structured input the chain layer feeds
	// into transcript-hash derivation.
	TranscriptInputs = reshare.TranscriptInputs
)

// Sentinel errors surfaced by VerifyActivation. Callers route on these
// via errors.Is.
var (
	// ErrActivationFailed signals that the activation signature did
	// not verify under the bound GroupKey.
	ErrActivationFailed = reshare.ErrActivationFailed
)

// VerifyActivation is the chain-level circuit-breaker. The new
// share-set is admitted iff the supplied ActivationCert's embedded
// signature verifies under the bound GroupKey AND the local-view
// transcript / exchange hashes match the cert's commitment.
//
// suite=nil resolves to the production default (Corona-SHA3). Returns
// ErrActivationFailed when the verifier closure rejects the embedded
// signature.
func VerifyActivation(
	cert *ActivationCert,
	localTranscriptHash [32]byte,
	localExchangeHash [32]byte,
	suite HashSuite,
	verifier func(message, signature []byte) bool,
) error {
	return reshare.VerifyActivation(cert, localTranscriptHash, localExchangeHash, suite, verifier)
}
