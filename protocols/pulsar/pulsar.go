// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package pulsar wires the Pulsar lattice threshold kernel
// (github.com/luxfi/pulsar) into the threshold orchestration layer's
// round-based protocol framework (github.com/luxfi/threshold/internal/round).
//
// Layer separation
//
//	pulsar (math kernel)
//	  ├── primitives, sign, threshold, reshare, dkg2, keyera
//	  └── single-process API; deterministic; KAT-replayable.
//
//	threshold/protocols/pulsar (this package)
//	  ├── round-based wrappers using internal/round/Session
//	  ├── party.ID, pool.Pool conventions
//	  └── distributed protocol entrypoints (StartFunc).
//
// This package is the equivalent of protocols/corona/ but built on
// the pulsar fork — proper t-of-n via general Shamir, lattice-correct
// Pedersen DKG (dkg2), full VSR with activation cert (reshare), and
// the keyera lifecycle (Bootstrap → Reshare* → Reanchor).
//
// Use this for new code. The protocols/corona/ package is kept for
// backwards compatibility but its refresh body is a stub and its DKG
// inherits the upstream pseudoinverse-recoverable Feldman commit (see
// luxcpp/crypto/corona/RED-DKG-REVIEW.md).
package pulsar

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/luxfi/corona/keyera"
	"github.com/luxfi/corona/threshold"

	"github.com/luxfi/threshold/pkg/party"
)

// Aliases for kernel types so callers do not have to import pulsar
// directly when they only need surface types.
type (
	// KeyEra is the Pulsar group lineage. One key era is opened by
	// Bootstrap and closed by Reanchor; epochs within an era rotate
	// shares via Reshare while preserving the GroupKey.
	KeyEra = keyera.KeyEra

	// EpochShareState is the per-epoch share distribution. Replaces
	// the legacy "EpochKeys" naming — distinguishes "share rotation"
	// from "key rotation".
	EpochShareState = keyera.EpochShareState

	// PulsarKeyEraID is a monotonically increasing identifier for a
	// key era; bumped only at Reanchor.
	PulsarKeyEraID = keyera.PulsarKeyEraID

	// PulsarGroupID identifies one Pulsar group for partitioned-set
	// deployments (each group has its own GroupKey lineage).
	PulsarGroupID = keyera.PulsarGroupID

	// GroupKey is the persistent (A, bTilde) public key. Pointer is
	// shared across all share states within a key era.
	GroupKey = threshold.GroupKey

	// KeyShare is one validator's share of the group key plus the
	// pairwise PRF/MAC material for the current epoch.
	KeyShare = threshold.KeyShare

	// Signer drives the 2-round Pulsar signing protocol for one party.
	Signer = threshold.Signer

	// Round1Data, Round2Data, Signature mirror the pulsar kernel.
	Round1Data = threshold.Round1Data
	Round2Data = threshold.Round2Data
	Signature  = threshold.Signature
)

// Errors returned by the package.
var (
	ErrEmptyValidators  = errors.New("pulsar: empty validator set")
	ErrInvalidThreshold = errors.New("pulsar: invalid threshold")
	ErrPartyNotInSet    = errors.New("pulsar: party not in committee")
)

// validatorIDs converts a party.ID slice into the canonical
// validator-string form pulsar/keyera consumes. Stable sort is the
// caller's responsibility (typically sorted-by-public-key per
// consensus convention).
func validatorIDs(ids []party.ID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = string(id)
	}
	return out
}

// Bootstrap runs the one-time trusted-dealer ceremony at chain genesis
// or governance-gated Reanchor. The trust is confined to genesis of
// the key era — after this returns, no party (including the dealer)
// retains the master secret.
//
// Foundation MUST coordinate Bootstrap as a publicly observable MPC
// ceremony at chain launch. The entropy MUST come from a verifiable
// commit-and-reveal among the genesis validators, and the dealer
// state MUST be erased before the ceremony closes.
//
// Use this in production for the genesis ceremony only. Subsequent
// epoch rotations go through Reshare, which never requires a trusted
// dealer.
func Bootstrap(t int, validators []party.ID, groupID PulsarGroupID, eraID PulsarKeyEraID, entropy io.Reader) (*KeyEra, error) {
	if len(validators) == 0 {
		return nil, ErrEmptyValidators
	}
	n := len(validators)
	if t < 1 || t > n {
		return nil, fmt.Errorf("%w: t=%d n=%d", ErrInvalidThreshold, t, n)
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	return keyera.Bootstrap(t, validatorIDs(validators), groupID, eraID, entropy)
}

// Reshare evolves an existing key era to a new committee while
// preserving GroupKey. The kernel runs in-process. For distributed
// deployments, the consensus layer wraps this in the full VSR exchange
// (commits, complaints, activation cert) defined in
// github.com/luxfi/corona/reshare.
//
// rand defaults to crypto/rand.Reader.
func Reshare(era *KeyEra, newValidators []party.ID, newThreshold int, randSource io.Reader) (*EpochShareState, error) {
	if era == nil {
		return nil, errors.New("pulsar: nil key era")
	}
	if len(newValidators) == 0 {
		return nil, ErrEmptyValidators
	}
	K := len(newValidators)
	if newThreshold < 1 || newThreshold > K {
		return nil, fmt.Errorf("%w: t=%d n=%d", ErrInvalidThreshold, newThreshold, K)
	}
	if randSource == nil {
		randSource = rand.Reader
	}
	return era.Reshare(validatorIDs(newValidators), newThreshold, randSource)
}

// Reanchor opens a new key era with a fresh GroupKey. Use ONLY for
// security-event response — long-tail share leakage, suspected
// master-secret compromise, or policy-driven key cycling. Requires
// governance authorization at the consensus layer.
//
// The new era's EraID is one greater than prev's; the new era's
// GenesisEpoch and starting Epoch continue from prev's last epoch.
func Reanchor(prev *KeyEra, t int, validators []party.ID, groupID PulsarGroupID, entropy io.Reader) (*KeyEra, error) {
	if len(validators) == 0 {
		return nil, ErrEmptyValidators
	}
	n := len(validators)
	if t < 1 || t > n {
		return nil, fmt.Errorf("%w: t=%d n=%d", ErrInvalidThreshold, t, n)
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	return keyera.Reanchor(prev, t, validatorIDs(validators), groupID, entropy)
}

// NewSigner constructs a Pulsar signer for one party from the per-epoch
// KeyShare emitted by Bootstrap or Reshare. The signer drives the
// 2-round signing protocol via Round1 / Round2 / Finalize.
func NewSigner(share *KeyShare) *Signer {
	return threshold.NewSigner(share)
}

// Verify checks a Pulsar signature against the persistent GroupKey.
// The GroupKey pointer is shared across every Reshare within a key
// era, so verifiers do not need to track epoch boundaries — any
// signature in the era verifies against the same GroupKey.
func Verify(gk *GroupKey, message string, sig *Signature) bool {
	return threshold.Verify(gk, message, sig)
}

// ShareForParty extracts the KeyShare for a given party.ID from an
// EpochShareState. Returns ErrPartyNotInSet if the party is not in
// the committee.
func ShareForParty(state *EpochShareState, id party.ID) (*KeyShare, error) {
	if state == nil {
		return nil, errors.New("pulsar: nil share state")
	}
	share, ok := state.Shares[string(id)]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrPartyNotInSet, id)
	}
	return share, nil
}
