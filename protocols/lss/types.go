package lss

import (
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
)

// Config represents the stored state of a party in the LSS protocol.
// It contains secret key material and should be safely stored.
type Config struct {
	// ID is the party's identifier
	ID party.ID

	// Group defines the elliptic curve being used
	Group curve.Curve

	// Threshold is the minimum number of parties required to sign
	Threshold int

	// Generation tracks the current re-sharing generation
	Generation uint64

	// SecretShare is this party's share of the master private key
	SecretShare curve.Scalar

	// PublicKey is the group's public key (remains constant across re-sharing)
	PublicKey curve.Point

	// PublicShares maps party IDs to their public key shares
	PublicShares map[party.ID]curve.Point

	// PartyIDs lists all current participants
	PartyIDs []party.ID
}

// ShardGeneration represents a snapshot of key shares at a specific generation
type ShardGeneration struct {
	Generation   uint64
	SecretShare  curve.Scalar
	PublicShares map[party.ID]curve.Point
	PartyIDs     []party.ID
	Threshold    int
}

// ReshareMessage represents messages exchanged during the re-sharing protocol
type ReshareMessage struct {
	Type       ReshareMessageType
	Generation uint64
	Data       []byte
}

// ReshareMessageType defines the types of messages in the re-sharing protocol
type ReshareMessageType uint8

const (
	// Phase 1: JVSS for auxiliary secrets
	ReshareTypeJVSSCommitment ReshareMessageType = iota
	ReshareTypeJVSSShare
	ReshareTypeJVSSComplaint
	
	// Phase 2: Blinded secret computation
	ReshareTypeBlindedShare
	
	// Phase 3: Inverse computation
	ReshareTypeBlindedProduct
	ReshareTypeInverseShare
	
	// Phase 4: Final share distribution
	ReshareTypeFinalShare
	ReshareTypeVerification
)

// SignatureRequest represents a request to sign a message
type SignatureRequest struct {
	MessageHash []byte
	Signers     []party.ID
	SessionID   []byte
}

// PartialSignature represents a party's contribution to a threshold signature
type PartialSignature struct {
	PartyID party.ID
	Share   curve.Scalar
}

// DealerRole defines the interface for the Bootstrap Dealer
type DealerRole interface {
	// InitiateReshare starts a new re-sharing protocol
	InitiateReshare(oldThreshold, newThreshold int, addParties, removeParties []party.ID) error
	
	// HandleReshareMessage processes incoming re-share protocol messages
	HandleReshareMessage(from party.ID, msg *ReshareMessage) error
	
	// GetCurrentGeneration returns the current shard generation
	GetCurrentGeneration() uint64
}

// CoordinatorRole defines the interface for the Signature Coordinator
type CoordinatorRole interface {
	// RequestSignature initiates a signing protocol
	RequestSignature(req *SignatureRequest) ([]byte, error)
	
	// HandlePartialSignature processes a partial signature from a party
	HandlePartialSignature(sig *PartialSignature) error
	
	// TriggerRollback requests a state rollback due to signing failure
	TriggerRollback(failedParties []party.ID) error
}

// PartyRole defines the interface for participant nodes
type PartyRole interface {
	// GetConfig returns the party's current configuration
	GetConfig() *Config
	
	// UpdateShare updates the party's secret share after re-sharing
	UpdateShare(newShare curve.Scalar, newGeneration uint64, newParties []party.ID) error
	
	// SaveGeneration persists a shard generation for potential rollback
	SaveGeneration(gen *ShardGeneration) error
	
	// RollbackToGeneration reverts to a previous shard generation
	RollbackToGeneration(generation uint64) error
	
	// GeneratePartialSignature creates this party's signature share
	GeneratePartialSignature(messageHash []byte, nonce curve.Scalar) (*PartialSignature, error)
}