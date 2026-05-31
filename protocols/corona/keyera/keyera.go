// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package keyera re-exports github.com/luxfi/corona/keyera through the
// threshold/protocols/corona alias surface. Downstream consumers
// (luxfi/consensus) target this import path so the consensus engine
// does not depend directly on the corona module.
//
// The re-exports are type aliases and thin function forwards; no
// behaviour change. See the upstream package for documentation of the
// underlying KeyEra lifecycle (Bootstrap → Reshare* → Reanchor).
package keyera

import (
	"io"

	"github.com/luxfi/corona/keyera"
)

// Identifier types for the Corona key-era lifecycle. CoronaKeyEraID
// is monotonic and bumped only at Reanchor; CoronaGroupID identifies
// one Corona group for partitioned-set deployments.
type (
	CoronaKeyEraID = keyera.CoronaKeyEraID
	CoronaGroupID  = keyera.CoronaGroupID
)

// Core lifecycle state.
type (
	KeyEra                = keyera.KeyEra
	EpochShareState       = keyera.EpochShareState
	BootstrapTranscript   = keyera.BootstrapTranscript
	PedersenContributions = keyera.PedersenContributions
	AbortEvidence         = keyera.AbortEvidence
)

// Bootstrap runs the one-time trusted-dealer ceremony at chain genesis
// or governance-gated Reanchor. See keyera.Bootstrap for the trust
// model.
func Bootstrap(t int, validators []string, groupID CoronaGroupID, eraID CoronaKeyEraID, entropy io.Reader) (*KeyEra, *BootstrapTranscript, error) {
	return keyera.Bootstrap(t, validators, groupID, eraID, entropy)
}

// BootstrapTrustedDealer is the legacy trusted-dealer-only entrypoint.
// Use Bootstrap (which routes through the public-BFT default) in new
// code.
func BootstrapTrustedDealer(t int, validators []string, groupID CoronaGroupID, eraID CoronaKeyEraID, entropy io.Reader) (*KeyEra, error) {
	return keyera.BootstrapTrustedDealer(t, validators, groupID, eraID, entropy)
}

// Reanchor opens a new key era with a fresh GroupKey. Use ONLY for
// security-event response — long-tail share leakage, suspected
// master-secret compromise, or policy-driven key cycling. Requires
// governance authorization at the consensus layer.
func Reanchor(prev *KeyEra, t int, validators []string, groupID CoronaGroupID, entropy io.Reader) (*KeyEra, *BootstrapTranscript, error) {
	return keyera.Reanchor(prev, t, validators, groupID, entropy)
}

// ReanchorTrustedDealer is the legacy trusted-dealer Reanchor path.
// Use Reanchor (Pedersen DKG) in new code.
func ReanchorTrustedDealer(prev *KeyEra, t int, validators []string, groupID CoronaGroupID, entropy io.Reader) (*KeyEra, error) {
	return keyera.ReanchorTrustedDealer(prev, t, validators, groupID, entropy)
}

// ExtractAbortEvidence pulls a typed AbortEvidence out of a wrapped
// bootstrap-abort error, returning nil if the error carries no
// evidence.
func ExtractAbortEvidence(err error) *AbortEvidence {
	return keyera.ExtractAbortEvidence(err)
}
