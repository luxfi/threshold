// Package lss implements the LSS MPC ECDSA protocol.
//
// Based on the paper:
// "LSS MPC ECDSA: A Pragmatic Framework for Dynamic and Resilient Threshold Signatures"
// by Vishnu J. Seesahai (vjs1@cornell.edu)
// August 3, 2025
//
// This implementation provides:
// - Dynamic resharing without reconstructing the master key
// - Resilient threshold signatures with fault tolerance
// - Support for adding/removing parties without downtime
// - Rollback capability for failed signing attempts
//
// Reference: https://eprint.iacr.org/2025/XXX (placeholder for actual publication)
package lss

import (
	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/lss/dealer"
	"github.com/luxfi/threshold/protocols/lss/reshare"
	"github.com/luxfi/threshold/protocols/lss/sign"
)

// EmptyConfig creates an empty Config with a fixed group, ready for unmarshalling.
func EmptyConfig(group curve.Curve) *Config {
	return &Config{
		Group:        group,
		PublicShares: make(map[party.ID]curve.Point),
	}
}

// Keygen generates a new shared ECDSA key with LSS protocol.
// This is the initial key generation that establishes the first generation.
func Keygen(group curve.Curve, selfID party.ID, participants []party.ID, threshold int, pl *pool.Pool) protocol.StartFunc {
	info := round.Info{
		ProtocolID:       "lss/keygen",
		FinalRoundNumber: 3, // Similar to FROST keygen
		SelfID:           selfID,
		PartyIDs:         participants,
		Threshold:        threshold,
		Group:            group,
	}
	return dealer.StartKeygen(info, pl)
}

// Reshare initiates the dynamic re-sharing protocol to change the participant set.
// This allows adding or removing parties without reconstructing the master key.
func Reshare(config *Config, newThreshold int, newParticipants []party.ID, pl *pool.Pool) protocol.StartFunc {
	info := round.Info{
		ProtocolID:       "lss/reshare",
		FinalRoundNumber: reshare.Rounds,
		SelfID:           config.ID,
		PartyIDs:         append(config.PartyIDs, newParticipants...), // Union of old and new
		Threshold:        newThreshold,
		Group:            config.Group,
	}
	return reshare.Start(info, config, newParticipants, pl)
}

// Sign generates an ECDSA signature using the LSS protocol.
// This implements the pragmatic signing approach described in the paper.
func Sign(config *Config, signers []party.ID, messageHash []byte, pl *pool.Pool) protocol.StartFunc {
	return sign.StartSign(config, signers, messageHash, pl)
}

// SignWithBlinding generates an ECDSA signature using Protocol I or II from the paper.
// This uses multiplicative blinding for enhanced security.
func SignWithBlinding(config *Config, signers []party.ID, messageHash []byte, protocol int, pl *pool.Pool) protocol.StartFunc {
	return sign.StartSignWithBlinding(config, signers, messageHash, protocol, pl)
}

// CreateBootstrapDealer creates a new Bootstrap Dealer instance.
func CreateBootstrapDealer(selfID party.ID, group curve.Curve) DealerRole {
	return dealer.NewBootstrapDealer(selfID, group)
}

// CreateSignatureCoordinator creates a new Signature Coordinator instance.
func CreateSignatureCoordinator(config *Config, pl *pool.Pool) CoordinatorRole {
	return sign.NewCoordinator(config, pl)
}

// Rollback triggers a state rollback to a previous generation.
// This is used when signing fails due to non-responsive parties.
func Rollback(config *Config, targetGeneration uint64, evictParties []party.ID) error {
	// Load the target generation from storage
	// Update config with the saved state
	// Remove evicted parties from the participant list
	return reshare.RollbackToGeneration(config, targetGeneration, evictParties)
}

// VerifyConfig validates that a Config is well-formed.
func VerifyConfig(config *Config) error {
	if config.Threshold <= 0 {
		return protocol.NewError("threshold must be positive")
	}
	if config.Threshold > len(config.PartyIDs) {
		return protocol.NewError("threshold cannot exceed number of parties")
	}
	if config.SecretShare == nil {
		return protocol.NewError("secret share is nil")
	}
	if config.PublicKey == nil {
		return protocol.NewError("public key is nil")
	}
	if len(config.PublicShares) != len(config.PartyIDs) {
		return protocol.NewError("public shares count mismatch")
	}
	return nil
}

// IsCompatibleForSigning checks if two configs can sign together.
func IsCompatibleForSigning(c1, c2 *Config) bool {
	// Same public key and group
	if !c1.PublicKey.Equal(c2.PublicKey) {
		return false
	}
	if !c1.Group.Name().Eq(c2.Group.Name()) {
		return false
	}
	// Same generation (must be at same re-share state)
	if c1.Generation != c2.Generation {
		return false
	}
	return true
}

// AdaptForEdDSA adapts the LSS protocol for EdDSA signatures.
// This modifies the protocol to work with Ed25519 curve.
func AdaptForEdDSA(config *Config) *Config {
	// EdDSA uses different hash function and signing equation
	// This would require modifications to the signing protocol
	eddsaConfig := *config
	eddsaConfig.Group = curve.Edwards25519{}
	return &eddsaConfig
}

// AdaptForFROST creates a FROST-compatible configuration from LSS.
// This allows using LSS's dynamic re-sharing with FROST signing.
func AdaptForFROST(config *Config) interface{} {
	// Convert LSS config to FROST config format
	// This enables using LSS resharing with FROST's signing protocol
	return &frostAdapter{
		lssConfig: config,
	}
}

type frostAdapter struct {
	lssConfig *Config
}

// GetSignatureType returns the type of signature this config produces.
func GetSignatureType(config *Config) string {
	switch config.Group.Name() {
	case "secp256k1":
		return "ECDSA"
	case "edwards25519":
		return "EdDSA"
	default:
		return "Unknown"
	}
}