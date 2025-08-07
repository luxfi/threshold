// Package protocol provides unified interfaces for threshold signature protocols.
package protocol

import (
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
)

// ThresholdConfig is a unified interface for all threshold protocol configurations.
// This allows LSS to work with any underlying protocol (CMP, FROST, etc.)
type ThresholdConfig interface {
	// Core identity and parameters
	GetID() party.ID
	GetThreshold() int
	GetGroup() curve.Curve
	
	// Key material
	GetPrivateShare() curve.Scalar
	GetPublicKey() (curve.Point, error)
	GetPublicShare(id party.ID) (curve.Point, error)
	
	// Protocol-specific data
	GetChainKey() []byte
	GetRID() []byte
	
	// Validation
	Validate() error
	IsCompatible(other ThresholdConfig) bool
}

// SignatureScheme represents the type of signature that can be produced
type SignatureScheme int

const (
	ECDSA SignatureScheme = iota
	Schnorr
	EdDSA
)

// ThresholdProtocol defines operations that any threshold protocol must support
type ThresholdProtocol interface {
	// Keygen creates a new distributed key
	Keygen(group curve.Curve, selfID party.ID, participants []party.ID, threshold int) (StartFunc, error)
	
	// Sign creates a signature with the given signers
	Sign(config ThresholdConfig, signers []party.ID, message []byte) (StartFunc, error)
	
	// Refresh updates shares without changing the key
	Refresh(config ThresholdConfig) (StartFunc, error)
	
	// GetScheme returns the signature scheme this protocol implements
	GetScheme() SignatureScheme
	
	// SupportsResharing indicates if the protocol supports dynamic resharing
	SupportsResharing() bool
}

// ThresholdSigner is a generic interface for signature generation
type ThresholdSigner[S any] interface {
	// Sign produces a signature of type S
	Sign(config ThresholdConfig, signers []party.ID, message []byte) (S, error)
	
	// Verify checks if a signature is valid
	Verify(signature S, publicKey curve.Point, message []byte) bool
}

// ReshareableProtocol extends ThresholdProtocol with resharing capabilities
type ReshareableProtocol interface {
	ThresholdProtocol
	
	// Reshare changes the participant set
	Reshare(config ThresholdConfig, newParticipants []party.ID, newThreshold int) (StartFunc, error)
	
	// AddParties adds new participants
	AddParties(config ThresholdConfig, newParties []party.ID) (StartFunc, error)
	
	// RemoveParties removes participants
	RemoveParties(config ThresholdConfig, partiesToRemove []party.ID) (StartFunc, error)
}

// ProtocolAdapter wraps a specific protocol implementation to provide a unified interface
type ProtocolAdapter[C ThresholdConfig] struct {
	protocol ThresholdProtocol
	config   C
}

// NewProtocolAdapter creates a new adapter for a specific protocol
func NewProtocolAdapter[C ThresholdConfig](protocol ThresholdProtocol, config C) *ProtocolAdapter[C] {
	return &ProtocolAdapter[C]{
		protocol: protocol,
		config:   config,
	}
}

// Execute runs a protocol operation with the wrapped configuration
func (a *ProtocolAdapter[C]) Execute(operation func(ThresholdConfig) (StartFunc, error)) (StartFunc, error) {
	return operation(a.config)
}