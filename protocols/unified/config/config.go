package config

import (
	"fmt"

	"github.com/luxfi/threshold/internal/types"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/paillier"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pedersen"
)

// SignatureType represents the type of signature scheme
type SignatureType int

const (
	// SignatureECDSA for ECDSA signatures (secp256k1)
	SignatureECDSA SignatureType = iota
	// SignatureEdDSA for EdDSA signatures (ed25519)
	SignatureEdDSA
	// SignatureSchnorr for Schnorr signatures (secp256k1)
	SignatureSchnorr
)

// String returns the string representation of the signature type
func (s SignatureType) String() string {
	switch s {
	case SignatureECDSA:
		return "ECDSA"
	case SignatureEdDSA:
		return "EdDSA"
	case SignatureSchnorr:
		return "Schnorr"
	default:
		return "Unknown"
	}
}

// UnifiedConfig represents a party's configuration supporting multiple signature schemes
// with dynamic resharing capabilities
type UnifiedConfig struct {
	// ID is this party's identifier
	ID party.ID

	// Threshold is the minimum number of parties needed to sign
	Threshold int

	// Generation tracks the current resharing generation
	// Incremented each time the configuration is reshared
	Generation uint64

	// PartyIDs contains all parties in the current configuration
	PartyIDs []party.ID

	// SignatureScheme defines which signature algorithm to use
	SignatureScheme SignatureType

	// Group defines the elliptic curve (secp256k1 for ECDSA/Schnorr, ed25519 for EdDSA)
	Group curve.Curve

	// SecretShare is this party's share of the secret key
	// Works for both ECDSA and EdDSA
	SecretShare curve.Scalar

	// PublicKey is the shared public key
	// Remains constant across resharing operations
	PublicKey curve.Point

	// VerificationShares maps party IDs to their public verification shares
	// Used to verify partial signatures
	VerificationShares map[party.ID]curve.Point

	// ChainKey for deterministic key derivation (optional)
	ChainKey types.RID

	// ECDSAExtensions contains ECDSA-specific configuration
	// Only populated when SignatureScheme == SignatureECDSA
	ECDSAExtensions *ECDSAExtensions

	// ReshareData contains temporary data during resharing
	// Cleared after resharing completes
	ReshareData *ReshareState
}

// ECDSAExtensions contains additional configuration needed for ECDSA
type ECDSAExtensions struct {
	// PaillierKey for multiplicative-to-additive share conversion
	PaillierKey *paillier.SecretKey

	// PedersenParams for zero-knowledge proofs
	PedersenParams *pedersen.Parameters

	// ElGamalKey for additional encryption (optional)
	ElGamalKey curve.Scalar

	// PublicPaillierKeys from all parties for verification
	PublicPaillierKeys map[party.ID]*paillier.PublicKey
}

// ReshareState tracks the state during a resharing operation
type ReshareState struct {
	// OldParties participating in the reshare (providing shares)
	OldParties []party.ID

	// NewParties receiving shares in the reshare
	NewParties []party.ID

	// NewThreshold after resharing completes
	NewThreshold int

	// BlindingFactors w and q for secure resharing
	WShare curve.Scalar
	QShare curve.Scalar

	// AuxiliaryData for the resharing protocol
	AuxiliaryData map[string][]byte
}

// Validate checks if the configuration is valid
func (c *UnifiedConfig) Validate() error {
	if c.ID == "" {
		return fmt.Errorf("party ID cannot be empty")
	}

	if c.Threshold < 1 {
		return fmt.Errorf("threshold must be at least 1")
	}

	if c.Threshold > len(c.PartyIDs) {
		return fmt.Errorf("threshold %d exceeds number of parties %d", c.Threshold, len(c.PartyIDs))
	}

	if c.Group == nil {
		return fmt.Errorf("group (curve) must be specified")
	}

	if c.SecretShare == nil || c.PublicKey == nil {
		return fmt.Errorf("secret share and public key must be set")
	}

	// Validate signature-specific requirements
	switch c.SignatureScheme {
	case SignatureECDSA:
		if c.ECDSAExtensions == nil {
			return fmt.Errorf("ECDSA extensions required for ECDSA signatures")
		}
		if c.ECDSAExtensions.PaillierKey == nil {
			return fmt.Errorf("Paillier key required for ECDSA")
		}
	case SignatureEdDSA, SignatureSchnorr:
		// No additional requirements for EdDSA/Schnorr
	default:
		return fmt.Errorf("unsupported signature scheme: %v", c.SignatureScheme)
	}

	// Verify we have verification shares for all parties
	if len(c.VerificationShares) != len(c.PartyIDs) {
		return fmt.Errorf("verification shares missing for some parties")
	}

	return nil
}

// CanSign checks if this party can participate in signing
func (c *UnifiedConfig) CanSign() bool {
	// Check if we're in the party list
	for _, p := range c.PartyIDs {
		if p == c.ID {
			return true
		}
	}
	return false
}

// IsResharing checks if a resharing operation is in progress
func (c *UnifiedConfig) IsResharing() bool {
	return c.ReshareData != nil
}

// Clone creates a deep copy of the configuration
func (c *UnifiedConfig) Clone() *UnifiedConfig {
	clone := &UnifiedConfig{
		ID:                 c.ID,
		Threshold:          c.Threshold,
		Generation:         c.Generation,
		PartyIDs:           make([]party.ID, len(c.PartyIDs)),
		SignatureScheme:    c.SignatureScheme,
		Group:              c.Group,
		SecretShare:        c.SecretShare,
		PublicKey:          c.PublicKey,
		VerificationShares: make(map[party.ID]curve.Point),
		ChainKey:           c.ChainKey,
	}

	copy(clone.PartyIDs, c.PartyIDs)

	for id, share := range c.VerificationShares {
		clone.VerificationShares[id] = share
	}

	if c.ECDSAExtensions != nil {
		clone.ECDSAExtensions = &ECDSAExtensions{
			PaillierKey:    c.ECDSAExtensions.PaillierKey,
			PedersenParams: c.ECDSAExtensions.PedersenParams,
		}
		if c.ECDSAExtensions.ElGamalKey != nil {
			clone.ECDSAExtensions.ElGamalKey = c.Group.NewScalar().Set(c.ECDSAExtensions.ElGamalKey)
		}
	}

	// Don't clone ReshareData as it's temporary

	return clone
}

// Compatible checks if two configs can be used together (e.g., for signing)
func (c *UnifiedConfig) Compatible(other *UnifiedConfig) bool {
	if c.SignatureScheme != other.SignatureScheme {
		return false
	}

	if !c.PublicKey.Equal(other.PublicKey) {
		return false
	}

	if c.Threshold != other.Threshold {
		return false
	}

	if c.Generation != other.Generation {
		return false
	}

	return true
}
