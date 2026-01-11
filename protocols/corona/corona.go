// Package corona implements a post-quantum lattice-based threshold signature scheme.
//
// Corona provides quantum-resistant threshold signatures using lattice cryptography,
// specifically designed for high-security applications requiring protection against
// quantum computer attacks. This package wraps the real implementation from
// github.com/luxfi/corona.
//
// The protocol supports:
//   - (t,n)-threshold signatures where t parties can sign
//   - Post-quantum security based on Module-LWE hardness
//   - Efficient key generation and signing
//   - Share refresh for proactive security
//   - Compatible with Lux's threshold infrastructure
package corona

import (
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/corona/config"
	"github.com/luxfi/threshold/protocols/corona/keygen"
	"github.com/luxfi/threshold/protocols/corona/refresh"
	"github.com/luxfi/threshold/protocols/corona/sign"

	realring "github.com/luxfi/corona/threshold"
)

// Config holds the configuration for a Corona threshold signing participant
type Config = config.Config

// KeygenOutput is the result of key generation
type KeygenOutput = keygen.KeygenOutput

// CoronaSignature is a completed threshold signature
type CoronaSignature = sign.CoronaSignature

// Keygen initiates the Corona threshold key generation protocol.
//
// This creates a new lattice-based key pair with the private key shared
// among n participants such that any t of them can collaborate to sign.
// Uses the real Corona implementation from github.com/luxfi/corona.
func Keygen(selfID party.ID, participants []party.ID, threshold int, pl *pool.Pool) protocol.StartFunc {
	return keygen.Start(selfID, participants, threshold, pl)
}

// Sign initiates the Corona threshold signing protocol.
//
// Given a message and a set of signers (at least threshold many),
// this produces a valid Corona signature using real lattice crypto
// from github.com/luxfi/corona.
//
// The keyShare and groupKey should be obtained from the KeygenOutput.
func Sign(cfg *Config, keyShare *realring.KeyShare, groupKey *realring.GroupKey, signers []party.ID, message []byte, pl *pool.Pool) protocol.StartFunc {
	return sign.Start(cfg, keyShare, groupKey, signers, message, pl)
}

// SignWithConfig initiates signing using only the config (for backward compatibility).
// This creates a new signer from the config's stored key material.
// Note: Requires the Config to have KeyShare and GroupKey set from keygen.
func SignWithConfig(cfg *Config, signers []party.ID, message []byte, pl *pool.Pool) protocol.StartFunc {
	// Use the real corona objects stored in config
	return sign.Start(cfg, cfg.KeyShare, cfg.GroupKey, signers, message, pl)
}

// Refresh initiates the share refresh protocol.
//
// This updates all shares while maintaining the same public key,
// providing proactive security against gradual key compromise.
func Refresh(cfg *Config, participants []party.ID, newThreshold int, pl *pool.Pool) protocol.StartFunc {
	return refresh.Start(cfg, participants, newThreshold, pl)
}

// VerifySignature verifies a Corona signature against a public key and message.
//
// This is a standalone verification that doesn't require threshold participation.
// Uses the real Corona verification from github.com/luxfi/corona.
func VerifySignature(publicKey []byte, message []byte, signature []byte) bool {
	return config.VerifySignature(publicKey, message, signature)
}

// VerifyWithGroupKey verifies a signature using the real corona group key.
func VerifyWithGroupKey(groupKey *realring.GroupKey, message string, sig *realring.Signature) bool {
	return realring.Verify(groupKey, message, sig)
}

// GenerateKeysDirectly generates threshold keys using the real corona directly.
// This bypasses the round-based protocol for simpler use cases.
func GenerateKeysDirectly(threshold, parties int) ([]*realring.KeyShare, *realring.GroupKey, error) {
	return realring.GenerateKeys(threshold, parties, nil)
}

// NewSignerFromKeyShare creates a real corona signer from a key share.
func NewSignerFromKeyShare(keyShare *realring.KeyShare) *realring.Signer {
	return realring.NewSigner(keyShare)
}
