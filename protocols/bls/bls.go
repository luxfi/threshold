// Package bls provides threshold BLS signature functionality
// by bridging the crypto/bls implementation with the threshold protocol framework.
package bls

import (
	"errors"
	"fmt"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
)

// Config holds BLS threshold signing configuration
type Config struct {
	// ID is this party's identifier
	ID party.ID

	// Threshold is the minimum number of parties needed to sign
	Threshold int

	// PublicKey is the aggregate public key
	PublicKey *bls.PublicKey

	// SecretShare is this party's secret key share
	SecretShare *bls.SecretKey

	// VerificationKeys are the public keys for each party's share
	VerificationKeys map[party.ID]*bls.PublicKey
}

// Sign creates a partial BLS signature with this party's share
func (c *Config) Sign(message []byte) (*bls.Signature, error) {
	if c.SecretShare == nil {
		return nil, errors.New("no secret share available")
	}

	// Sign with our share
	sig := bls.Sign(c.SecretShare, message)
	return sig, nil
}

// AggregateSignatures combines threshold signatures into a single signature
func AggregateSignatures(signatures []*bls.Signature, threshold int) (*bls.Signature, error) {
	if len(signatures) < threshold {
		return nil, fmt.Errorf("insufficient signatures: have %d, need %d", len(signatures), threshold)
	}

	// Aggregate the threshold signatures
	aggregated, err := bls.AggregateSignatures(signatures[:threshold])
	if err != nil {
		return nil, err
	}
	return aggregated, nil
}

// VerifyPartialSignature verifies a signature share from a specific party
func (c *Config) VerifyPartialSignature(from party.ID, message []byte, sig *bls.Signature) bool {
	pubKey, ok := c.VerificationKeys[from]
	if !ok {
		return false
	}

	return bls.Verify(pubKey, sig, message)
}

// VerifyAggregateSignature verifies the final aggregated signature
func (c *Config) VerifyAggregateSignature(message []byte, sig *bls.Signature) bool {
	return bls.Verify(c.PublicKey, sig, message)
}

// Keygen creates a new BLS threshold key generation protocol
func Keygen(selfID party.ID, participants []party.ID, threshold int, pl *pool.Pool) protocol.StartFunc {
	// This would initiate the key generation protocol
	// using VSS (Verifiable Secret Sharing) for BLS keys
	return func(sessionID []byte) (round.Session, error) {
		// Implementation would go here
		// This would use a similar round structure to FROST/LSS
		// but with BLS-specific key generation
		return nil, errors.New("BLS threshold keygen not yet implemented")
	}
}

// SignProtocol creates a threshold BLS signing protocol
func SignProtocol(config *Config, signers []party.ID, message []byte, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		// This would coordinate the threshold signing
		// Each party signs with their share
		// Then signatures are aggregated
		return nil, errors.New("BLS threshold signing protocol not yet implemented")
	}
}
