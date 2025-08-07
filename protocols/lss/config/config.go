// Package config implements the LSS configuration and storage
package config

import (
	"errors"
	"fmt"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/party"
)

// Config represents the long-term storage for an LSS party.
type Config struct {
	// ID is this party's identifier
	ID party.ID

	// Group defines the elliptic curve we're using
	Group curve.Curve

	// Threshold is the minimum number of parties needed to sign
	Threshold int

	// Generation tracks the current resharing generation
	Generation uint64

	// ECDSA is this party's share of the master private key
	ECDSA curve.Scalar

	// Public maps party IDs to their public key shares
	Public map[party.ID]*Public

	// ChainKey is used for deriving per-signature randomness
	ChainKey []byte

	// RID is the unique identifier for this party's keygen session
	RID []byte
}

// Public represents the public information for a party
type Public struct {
	// ECDSA is the public key share (g^share_i)
	ECDSA curve.Point
}

// EmptyConfig creates an empty Config with a specific group, ready for unmarshalling.
func EmptyConfig(group curve.Curve) *Config {
	return &Config{
		Group:  group,
		Public: make(map[party.ID]*Public),
	}
}

// PublicPoint returns the combined public key using Lagrange interpolation
func (c *Config) PublicPoint() (curve.Point, error) {
	partyIDs := make([]party.ID, 0, len(c.Public))
	for j := range c.Public {
		partyIDs = append(partyIDs, j)
	}
	
	// Use first threshold parties for interpolation
	if len(partyIDs) < c.Threshold {
		return nil, fmt.Errorf("insufficient parties: have %d, need %d", len(partyIDs), c.Threshold)
	}
	
	contributingParties := partyIDs[:c.Threshold]
	lagrange := polynomial.Lagrange(c.Group, contributingParties)
	
	sum := c.Group.NewPoint()
	for _, j := range contributingParties {
		if coeff, exists := lagrange[j]; exists {
			partyJ := c.Public[j]
			contribution := coeff.Act(partyJ.ECDSA)
			sum = sum.Add(contribution)
		}
	}
	
	return sum, nil
}

// PartyIDs returns a sorted slice of party IDs.
func (c *Config) PartyIDs() party.IDSlice {
	ids := make([]party.ID, 0, len(c.Public))
	for id := range c.Public {
		ids = append(ids, id)
	}
	return party.IDSlice(ids)
}

// PublicKey returns the combined public key (backward compatibility)
func (c *Config) PublicKey() (curve.Point, error) {
	return c.PublicPoint()
}

// Validate checks if the config is well-formed
func (c *Config) Validate() error {
	if c.Group == nil {
		return errors.New("lss/config: missing group")
	}
	if c.ID == "" {
		return errors.New("lss/config: missing ID")
	}
	if c.ECDSA == nil {
		return errors.New("lss/config: missing ECDSA share")
	}
	if c.Threshold < 1 {
		return errors.New("lss/config: invalid threshold")
	}
	if c.Threshold > len(c.Public) {
		return errors.New("lss/config: threshold exceeds party count")
	}
	if len(c.ChainKey) == 0 {
		return errors.New("lss/config: missing chain key")
	}
	if len(c.RID) == 0 {
		return errors.New("lss/config: missing RID")
	}
	
	// Verify all public shares are present
	for id, pub := range c.Public {
		if pub == nil {
			return fmt.Errorf("lss/config: missing public share for %s", id)
		}
		if pub.ECDSA == nil {
			return fmt.Errorf("lss/config: missing ECDSA public share for %s", id)
		}
	}
	
	return nil
}

// Copy creates a deep copy of the config
func (c *Config) Copy() *Config {
	newConfig := &Config{
		ID:         c.ID,
		Group:      c.Group,
		Threshold:  c.Threshold,
		Generation: c.Generation,
		ECDSA:      c.ECDSA,
		Public:     make(map[party.ID]*Public),
		ChainKey:   append([]byte(nil), c.ChainKey...),
		RID:        append([]byte(nil), c.RID...),
	}
	
	for id, pub := range c.Public {
		newConfig.Public[id] = &Public{
			ECDSA: pub.ECDSA,
		}
	}
	
	return newConfig
}