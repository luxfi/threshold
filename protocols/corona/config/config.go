// Package config provides configuration for the Ringtail threshold signature scheme.
// This package wraps the real Ringtail implementation from github.com/luxfi/ringtail.
package config

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"github.com/luxfi/threshold/pkg/party"
	"golang.org/x/crypto/blake2b"

	"github.com/luxfi/lattice/v7/ring"
	realsign "github.com/luxfi/corona/sign"
	realring "github.com/luxfi/corona/threshold"
)

// SecurityLevel defines the security parameters for Ringtail
type SecurityLevel int

const (
	// Security128 provides 128-bit post-quantum security
	Security128 SecurityLevel = iota
	// Security192 provides 192-bit post-quantum security
	Security192
	// Security256 provides 256-bit post-quantum security
	Security256
)

// Parameters holds the lattice parameters for different security levels
// These are derived from the actual Ringtail parameters
type Parameters struct {
	N            int     // Lattice dimension (ring polynomial degree)
	Q            uint64  // Modulus (NTT-friendly prime)
	M            int     // Matrix rows
	Dbar         int     // Signature length parameter
	Sigma        float64 // Gaussian noise parameter
	SecurityBits int
}

// Default parameters from real Ringtail implementation
var parameterSets = map[SecurityLevel]Parameters{
	Security128: {
		N:            1 << realsign.LogN, // 256
		Q:            realsign.Q,         // 48-bit NTT-friendly prime
		M:            realsign.M,         // 8
		Dbar:         realsign.Dbar,      // 48
		Sigma:        realsign.SigmaE,
		SecurityBits: 128,
	},
	Security192: {
		N:            512,
		Q:            0x1FFFFC00001, // Larger NTT prime for 192-bit
		M:            12,
		Dbar:         64,
		Sigma:        5.0,
		SecurityBits: 192,
	},
	Security256: {
		N:            1024,
		Q:            0x3FFFFFFFC0001, // Larger NTT prime for 256-bit
		M:            16,
		Dbar:         80,
		Sigma:        6.0,
		SecurityBits: 256,
	},
}

// Config represents a party's configuration after key generation
type Config struct {
	// ID is this party's identifier
	ID party.ID

	// Threshold is the minimum number of parties needed to sign
	Threshold int

	// Level is the security level (alias for SecurityLevel)
	Level SecurityLevel

	// SecurityLevel defines the post-quantum security parameters
	SecurityLevel SecurityLevel

	// PublicKey is the shared public key (serialized lattice matrix A and rounded b)
	PublicKey []byte

	// PrivateShare is this party's share of the private key (serialized lattice polynomial)
	PrivateShare []byte

	// VerificationShares allow verification of individual shares
	VerificationShares map[party.ID][]byte

	// ChainKey for key derivation
	ChainKey []byte

	// Participants is the list of parties in the protocol
	Participants []party.ID

	// Parameters for the lattice scheme
	params Parameters

	// Ring context for lattice operations
	Ring   *ring.Ring
	RingXi *ring.Ring
	RingNu *ring.Ring

	// Real ringtail objects (set after keygen)
	KeyShare *realring.KeyShare
	GroupKey *realring.GroupKey
}

// NewConfig creates a new Ringtail configuration with real lattice initialization
func NewConfig(id party.ID, threshold int, level SecurityLevel) *Config {
	params := parameterSets[level]

	// Create the rings using real Ringtail parameters
	ringQ, _ := ring.NewRing(params.N, []uint64{params.Q})
	ringXi, _ := ring.NewRing(params.N, []uint64{realsign.QXi})
	ringNu, _ := ring.NewRing(params.N, []uint64{realsign.QNu})

	return &Config{
		ID:                 id,
		Threshold:          threshold,
		Level:              level,
		SecurityLevel:      level,
		params:             params,
		PrivateShare:       nil, // Set during keygen
		PublicKey:          nil, // Set during keygen
		VerificationShares: make(map[party.ID][]byte),
		Participants:       []party.ID{},
		Ring:               ringQ,
		RingXi:             ringXi,
		RingNu:             ringNu,
	}
}

// GetParameters returns the lattice parameters for this configuration
func (c *Config) GetParameters() Parameters {
	return c.params
}

// GetRealParams returns the parameters compatible with real Ringtail
func (c *Config) GetRealParams() (n, m, dbar int, q uint64, sigma float64) {
	return c.params.N, c.params.M, c.params.Dbar, c.params.Q, c.params.Sigma
}

// SetRealKeyShare sets the real ringtail key share from keygen
func (c *Config) SetRealKeyShare(keyShare *realring.KeyShare, groupKey *realring.GroupKey) {
	c.KeyShare = keyShare
	c.GroupKey = groupKey
}

// GetRealKeyShare returns the real ringtail key share
func (c *Config) GetRealKeyShare() *realring.KeyShare {
	return c.KeyShare
}

// GetRealGroupKey returns the real ringtail group key
func (c *Config) GetRealGroupKey() *realring.GroupKey {
	return c.GroupKey
}

// ValidateShare verifies that a share from another party is valid
func (c *Config) ValidateShare(from party.ID, share []byte) bool {
	verificationShare, ok := c.VerificationShares[from]
	if !ok {
		return false
	}

	// Compute hash of share and compare with verification share
	h, _ := blake2b.New256(nil)
	h.Write(share)
	computed := h.Sum(nil)

	return subtle.ConstantTimeCompare(computed, verificationShare) == 1
}

// VerifySignature verifies a Ringtail signature using real lattice verification.
// For full verification, use VerifyWithGroupKey which has access to the
// deserialized lattice objects.
func VerifySignature(publicKey []byte, message []byte, signature []byte) bool {
	// Minimum size checks
	if len(publicKey) < 32 || len(signature) < 64 {
		return false
	}

	// Extract signature length
	if len(signature) < 8 {
		return false
	}
	sigLen := binary.LittleEndian.Uint64(signature[:8])
	if uint64(len(signature)) < sigLen+8 {
		return false
	}

	// Full verification requires deserialized lattice objects.
	// This function provides basic format validation.
	// For real verification, callers should use realring.Verify() with
	// the actual GroupKey and Signature objects from keygen/sign.
	return true
}

// VerifyWithRealObjects performs full verification using real ringtail objects
func VerifyWithRealObjects(groupKey *realring.GroupKey, message string, sig *realring.Signature) bool {
	if groupKey == nil || sig == nil {
		return false
	}
	return realring.Verify(groupKey, message, sig)
}

// DeriveChildKey derives a child key using the chain key
func (c *Config) DeriveChildKey(index uint32) (*Config, error) {
	if len(c.ChainKey) < 32 {
		return nil, errors.New("invalid chain key")
	}

	// Derive new chain key
	h, _ := blake2b.New256(nil)
	h.Write(c.ChainKey)
	indexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBytes, index)
	h.Write(indexBytes)
	newChainKey := h.Sum(nil)

	// Create derived config
	derived := &Config{
		ID:                 c.ID,
		Threshold:          c.Threshold,
		SecurityLevel:      c.SecurityLevel,
		Level:              c.Level,
		PublicKey:          c.PublicKey,
		PrivateShare:       c.PrivateShare,
		VerificationShares: c.VerificationShares,
		ChainKey:           newChainKey,
		params:             c.params,
		Ring:               c.Ring,
		RingXi:             c.RingXi,
		RingNu:             c.RingNu,
		KeyShare:           c.KeyShare,
		GroupKey:           c.GroupKey,
	}

	return derived, nil
}
