// Package lss implements the LSS MPC ECDSA protocol.
//
// Based on the paper:
// "LSS MPC ECDSA: A Pragmatic Framework for Dynamic and Resilient Threshold Signatures"
// by Vishnu J. Seesahai
//
// This implementation provides:
// - Dynamic resharing without reconstructing the master key
// - Resilient threshold signatures with fault tolerance
// - Support for adding/removing parties without downtime
// - Rollback capability for failed signing attempts
package lss

import (
	"errors"
	"fmt"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/lss/config"
	"github.com/luxfi/threshold/protocols/lss/keygen"
	"github.com/luxfi/threshold/protocols/lss/reshare"
	"github.com/luxfi/threshold/protocols/lss/sign"
)

// Config represents the configuration for the LSS protocol.
// This is an alias to the config.Config type for backward compatibility.
type Config = config.Config

// EmptyConfig creates an empty Config with a fixed group, ready for unmarshalling.
func EmptyConfig(group curve.Curve) *config.Config {
	return config.EmptyConfig(group)
}

// Keygen generates a new shared ECDSA key with LSS protocol.
func Keygen(group curve.Curve, selfID party.ID, participants []party.ID, threshold int, pl *pool.Pool) protocol.StartFunc {
	if threshold < 1 || threshold > len(participants) {
		return func(sessionID []byte) (round.Session, error) {
			return nil, fmt.Errorf("lss: invalid threshold %d for %d parties", threshold, len(participants))
		}
	}

	return keygen.Start(selfID, participants, threshold, group, pl)
}

// Refresh refreshes the key shares without changing the public key or membership.
func Refresh(c *config.Config, pl *pool.Pool) protocol.StartFunc {
	participants := c.PartyIDs()
	return reshare.Start(c, participants, c.Threshold, pl)
}

// Reshare performs dynamic resharing to change the participant set.
func Reshare(c *config.Config, newParticipants []party.ID, newThreshold int, pl *pool.Pool) protocol.StartFunc {
	if newThreshold < 1 || newThreshold > len(newParticipants) {
		return func(sessionID []byte) (round.Session, error) {
			return nil, fmt.Errorf("lss: invalid threshold %d for %d parties", newThreshold, len(newParticipants))
		}
	}

	return reshare.Start(c, newParticipants, newThreshold, pl)
}

// Sign generates an ECDSA signature using the LSS protocol.
func Sign(c *config.Config, signers []party.ID, messageHash []byte, pl *pool.Pool) protocol.StartFunc {
	if len(signers) < c.Threshold {
		return func(sessionID []byte) (round.Session, error) {
			return nil, fmt.Errorf("lss: insufficient signers: have %d, need %d", len(signers), c.Threshold)
		}
	}

	if len(messageHash) != 32 {
		return func(sessionID []byte) (round.Session, error) {
			return nil, errors.New("lss: message hash must be 32 bytes")
		}
	}

	return sign.Start(c, signers, messageHash, pl)
}

// VerifyConfig validates that a Config is well-formed.
func VerifyConfig(c *config.Config) error {
	return c.Validate()
}

// IsCompatibleForSigning checks if two configs can sign together.
func IsCompatibleForSigning(c1, c2 *config.Config) bool {
	// Same public key and group
	p1, err1 := c1.PublicPoint()
	p2, err2 := c2.PublicPoint()
	if err1 != nil || err2 != nil {
		return false
	}
	if !p1.Equal(p2) {
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

// ReshareMessageType represents the type of reshare message
type ReshareMessageType int

const (
	// ReshareTypeJVSSCommitment is a JVSS commitment message
	ReshareTypeJVSSCommitment ReshareMessageType = iota
	// ReshareTypeBlindedShare is a blinded share message
	ReshareTypeBlindedShare
	// ReshareTypeBlindedProduct is a blinded product message
	ReshareTypeBlindedProduct
	// ReshareTypeVerification is a verification message
	ReshareTypeVerification
)

// ReshareMessage represents a message in the reshare protocol
type ReshareMessage struct {
	Type       ReshareMessageType
	Generation uint64
	Data       []byte // Serialized message data
}
