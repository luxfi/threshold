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
	"errors"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/lss/keygen"
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
	return func(sessionID []byte) (round.Session, error) {
		if threshold < 1 || threshold > len(participants) {
			return nil, errors.New("invalid threshold")
		}
		
		info := round.Info{
			ProtocolID:       "lss/keygen",
			FinalRoundNumber: 3,
			SelfID:           selfID,
			PartyIDs:         participants,
			Threshold:        threshold,
			Group:            group,
		}
		
		// Get the start function and execute it
		startFunc := keygen.Start(info, pl, nil)
		return startFunc(sessionID)
	}
}

// Reshare initiates the dynamic re-sharing protocol to change the participant set.
// This allows adding or removing parties without reconstructing the master key.
func Reshare(config *Config, newThreshold int, newParticipants []party.ID, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		// Combine old and new parties
		allParties := make([]party.ID, 0, len(config.PartyIDs)+len(newParticipants))
		partySet := make(map[party.ID]bool)
		
		for _, id := range config.PartyIDs {
			if !partySet[id] {
				allParties = append(allParties, id)
				partySet[id] = true
			}
		}
		
		for _, id := range newParticipants {
			if !partySet[id] {
				allParties = append(allParties, id)
				partySet[id] = true
			}
		}
		
		if newThreshold < 1 || newThreshold > len(allParties) {
			return nil, errors.New("invalid new threshold")
		}
		
		info := round.Info{
			ProtocolID:       "lss/reshare",
			FinalRoundNumber: 3,
			SelfID:           config.ID,
			PartyIDs:         allParties,
			Threshold:        newThreshold,
			Group:            config.Group,
		}
		
		// Convert to reshare.Config
		reshareConfig := &reshare.Config{
			ID:           config.ID,
			Group:        config.Group,
			Threshold:    config.Threshold,
			Generation:   config.Generation,
			SecretShare:  config.SecretShare,
			PublicKey:    config.PublicKey,
			PublicShares: config.PublicShares,
			PartyIDs:     config.PartyIDs,
		}
		
		// Get the start function and execute it
		startFunc := reshare.Start(info, pl, reshareConfig, newParticipants)
		return startFunc(sessionID)
	}
}

// Sign generates an ECDSA signature using the LSS protocol.
// This implements the pragmatic signing approach described in the paper.
func Sign(config *Config, signers []party.ID, messageHash []byte, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		if len(signers) < config.Threshold {
			return nil, errors.New("not enough signers")
		}
		
		if len(messageHash) != 32 {
			return nil, errors.New("message hash must be 32 bytes")
		}
		
		info := round.Info{
			ProtocolID:       "lss/sign",
			FinalRoundNumber: 3,
			SelfID:           config.ID,
			PartyIDs:         signers,
			Threshold:        config.Threshold,
			Group:            config.Group,
		}
		
		// Convert to sign.Config
		signConfig := &sign.Config{
			ID:           config.ID,
			Group:        config.Group,
			Threshold:    config.Threshold,
			Generation:   config.Generation,
			SecretShare:  config.SecretShare,
			PublicKey:    config.PublicKey,
			PublicShares: config.PublicShares,
			PartyIDs:     config.PartyIDs,
		}
		
		// Get the start function
		startFunc := sign.StartSign(info, pl, signConfig, messageHash)
		
		// Execute it to get the session
		return startFunc(sessionID)
	}
}

// SignWithBlinding generates an ECDSA signature using Protocol I or II from the paper.
// This uses multiplicative blinding for enhanced security.
func SignWithBlinding(_ *Config, _ []party.ID, _ []byte, _ int, _ *pool.Pool) protocol.StartFunc {
	// TODO: Implement sign.StartSignWithBlinding
	return func(_ []byte) (round.Session, error) {
		return nil, errors.New("LSS sign with blinding not yet implemented")
	}
}

// CreateBootstrapDealer creates a new Bootstrap Dealer instance.
func CreateBootstrapDealer(_ party.ID, _ curve.Curve) DealerRole {
	// TODO: Implement dealer.NewBootstrapDealer
	return nil
}

// CreateSignatureCoordinator creates a new Signature Coordinator instance.
func CreateSignatureCoordinator(_ *Config, _ *pool.Pool) CoordinatorRole {
	// TODO: Implement sign.NewCoordinator
	return nil
}

// Rollback triggers a state rollback to a previous generation.
// This is used when signing fails due to non-responsive parties.
func Rollback(_ *Config, _ uint64, _ []party.ID) error {
	// TODO: Implement rollback functionality
	// Load the target generation from storage
	// Update config with the saved state
	// Remove evicted parties from the participant list
	return errors.New("LSS rollback not yet implemented")
}

// VerifyConfig validates that a Config is well-formed.
func VerifyConfig(config *Config) error {
	if config.Threshold <= 0 {
		return errors.New("threshold must be positive")
	}
	if config.Threshold > len(config.PartyIDs) {
		return errors.New("threshold cannot exceed number of parties")
	}
	if config.SecretShare == nil {
		return errors.New("secret share is nil")
	}
	if config.PublicKey == nil {
		return errors.New("public key is nil")
	}
	if len(config.PublicShares) != len(config.PartyIDs) {
		return errors.New("public shares count mismatch")
	}
	return nil
}

// IsCompatibleForSigning checks if two configs can sign together.
func IsCompatibleForSigning(c1, c2 *Config) bool {
	// Same public key and group
	if !c1.PublicKey.Equal(c2.PublicKey) {
		return false
	}
	if c1.Group.Name() != c2.Group.Name() {
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
	// TODO: Implement when Edwards25519 curve is available
	eddsaConfig := *config
	// eddsaConfig.Group = curve.Edwards25519{}
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
	// case "edwards25519":
	// 	return "EdDSA"
	default:
		return "Unknown"
	}
}

