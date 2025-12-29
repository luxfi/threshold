// UNSAFE: This implementation is NOT a real threshold scheme.
//   - Every party stores the full master key (line ~374: UnderlyingKey: masterSK)
//   - PartialDecrypt returns an HMAC tag, not a partial decryption
//   - CombineShares ignores partials and runs single-party decryption
//
// DO NOT USE in production. Refused security review by Red 2026-04-28.
//
// Real threshold FHE requires:
//  1. Shamir-split master secret key (each party gets a SHARE, not the full key)
//  2. PartialDecrypt produces a partial decryption (lattice noise + share contribution)
//  3. CombineShares Lagrange-interpolates partials to recover the cleartext
//
// Migration path: route through luxfi/lattice threshold protocol primitives
// (which DO implement real Shamir share generation + partial-decrypt + combine).
// See lps/LP-137-TFHE-REAL-THRESHOLD-SPEC.md.
//
// Test opt-in: set LUX_ALLOW_FAKE_TFHE_FOR_TESTING_ONLY=1 to bypass the
// fail-loud panics at every entry point. Production must crash if reached.
//
// Package tfhe provides the HIGH-LEVEL orchestration layer for Threshold FHE.
//
// This package wraps github.com/luxfi/fhe's threshold functionality and
// integrates it with the threshold protocol framework. It provides:
//
//   - Threshold key generation using the threshold party system
//   - Threshold decryption with partial shares
//   - Threshold RNG using T-Chain network
//   - Integration with other threshold protocols (CMP, FROST, etc.)
//
// For single-party FHE operations, use github.com/luxfi/fhe directly.
// This package is for multi-party threshold operations only.
//
// References:
//   - LP-137: TFHE Real Threshold Spec (lps/LP-137-TFHE-REAL-THRESHOLD-SPEC.md)
//   - LP-5703: Threshold Cryptography (lux/threshold)
//   - LP-5702: Fully Homomorphic Encryption (lux/fhe)
//   - LP-5704: Composable Cryptographic Architecture
//
// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause
package tfhe

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/luxfi/fhe"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
)

// unsafeTFHEEnvVar gates the fake-threshold implementation. Tests must set
// LUX_ALLOW_FAKE_TFHE_FOR_TESTING_ONLY=1 to opt in. Production paths panic.
const unsafeTFHEEnvVar = "LUX_ALLOW_FAKE_TFHE_FOR_TESTING_ONLY"

// unsafePanicMsg is the standard refusal message emitted at every entry point
// of the fake-threshold implementation when the opt-in env var is unset.
const unsafePanicMsg = "tfhe: UNSAFE fake-threshold implementation reached without " +
	unsafeTFHEEnvVar + "=1. " +
	"Every party stores the full master key; PartialDecrypt returns an HMAC tag; " +
	"CombineShares runs single-party decrypt. " +
	"DO NOT USE in production. See lps/LP-137-TFHE-REAL-THRESHOLD-SPEC.md."

// guardUnsafe panics unless the test opt-in env var is set. Called from every
// entry point of the fake-threshold implementation.
func guardUnsafe() {
	if os.Getenv(unsafeTFHEEnvVar) != "1" {
		panic(unsafePanicMsg)
	}
}

var (
	// ErrInsufficientShares is returned when fewer than threshold shares are provided.
	ErrInsufficientShares = errors.New("tfhe: insufficient decryption shares")

	// ErrInvalidShare is returned when a decryption share fails validation.
	ErrInvalidShare = errors.New("tfhe: invalid decryption share")

	// ErrKeyMismatch is returned when shares are from different key generations.
	ErrKeyMismatch = errors.New("tfhe: key generation mismatch")

	// ErrNotInitialized is returned when operations are attempted before initialization.
	ErrNotInitialized = errors.New("tfhe: not initialized")

	// ErrThresholdNetworkUnavailable is returned when T-Chain is unreachable.
	ErrThresholdNetworkUnavailable = errors.New("tfhe: threshold network unavailable")
)

// Config holds the threshold FHE configuration for a party.
type Config struct {
	// Threshold is t in t-of-n (minimum shares needed to decrypt).
	Threshold int

	// TotalParties is n in t-of-n.
	TotalParties int

	// PartyID identifies this party.
	PartyID party.ID

	// Generation is the key generation epoch (increments on key refresh).
	Generation uint64

	// FHEParams are the underlying FHE parameters.
	FHEParams fhe.Parameters

	// PublicKey is the collective FHE public key.
	PublicKey *fhe.PublicKey

	// SecretKeyShare is this party's share of the secret key.
	SecretKeyShare *SecretKeyShare
}

// SecretKeyShare represents a party's share of the FHE secret key.
type SecretKeyShare struct {
	// PartyID identifies the share owner.
	PartyID party.ID

	// Index is the party's index (0-based).
	Index int

	// Generation is the key generation epoch.
	Generation uint64

	// UnderlyingKey is the party's FHE secret key share.
	// Each party holds a Shamir share of the master secret key.
	UnderlyingKey *fhe.SecretKey

	// LambdaCoeff is the Lagrange coefficient for this party.
	LambdaCoeff []byte
}

// DecryptionShare represents a partial decryption from one party.
type DecryptionShare struct {
	// PartyID identifies the share creator.
	PartyID party.ID

	// Index is the party's index.
	Index int

	// Generation is the key generation epoch.
	Generation uint64

	// CiphertextHash identifies which ciphertext this decrypts.
	CiphertextHash [32]byte

	// PartialResult is the partial decryption result.
	PartialResult []byte

	// Proof is an optional ZK proof of correct partial decryption.
	Proof []byte
}

// Protocol orchestrates threshold FHE operations.
type Protocol struct {
	config *Config
	pool   *pool.Pool

	// FHE components from github.com/luxfi/fhe
	encryptor *fhe.BitwiseEncryptor
	decryptor *fhe.BitwiseDecryptor
	evaluator *fhe.BitwiseEvaluator

	// Threshold RNG using T-Chain
	thresholdRNG *fhe.ThresholdRNG

	// Collected decryption shares
	shares   map[party.ID]*DecryptionShare
	sharesMu sync.Mutex
}

// NewProtocol creates a new threshold FHE protocol instance.
//
// UNSAFE: panics in production unless LUX_ALLOW_FAKE_TFHE_FOR_TESTING_ONLY=1.
// See package doc for migration to real threshold FHE.
func NewProtocol(config *Config, pl *pool.Pool) (*Protocol, error) {
	guardUnsafe()
	if config == nil {
		return nil, ErrNotInitialized
	}
	if config.SecretKeyShare == nil {
		return nil, fmt.Errorf("config.SecretKeyShare is required")
	}

	p := &Protocol{
		config: config,
		pool:   pl,
		shares: make(map[party.ID]*DecryptionShare),
	}

	// Initialize FHE encryptor/decryptor from the secret key share
	if config.SecretKeyShare.UnderlyingKey != nil {
		p.encryptor = fhe.NewBitwiseEncryptor(config.FHEParams, config.SecretKeyShare.UnderlyingKey)
		p.decryptor = fhe.NewBitwiseDecryptor(config.FHEParams, config.SecretKeyShare.UnderlyingKey)
	}

	return p, nil
}

// SetThresholdRNG sets the threshold RNG provider for this protocol.
// This connects to the T-Chain for threshold randomness.
func (p *Protocol) SetThresholdRNG(provider fhe.ThresholdRNGProvider) {
	rngConfig := &fhe.ThresholdRNGConfig{
		Provider:        provider,
		FallbackEnabled: true,
	}

	var pk *fhe.PublicKey
	if p.config.PublicKey != nil {
		pk = p.config.PublicKey
	}

	p.thresholdRNG = fhe.NewThresholdRNG(
		p.config.FHEParams,
		p.config.SecretKeyShare.UnderlyingKey,
		pk,
		rngConfig,
	)
}

// CreateDecryptionShare creates a partial decryption share for a ciphertext.
func (p *Protocol) CreateDecryptionShare(ctx context.Context, ct *fhe.BitCiphertext) (*DecryptionShare, error) {
	if p.decryptor == nil {
		return nil, fmt.Errorf("decryptor not initialized")
	}

	// Compute hash of ciphertext for identification
	ctHash := computeCiphertextHash(ct)

	// Create partial decryption using our secret key share
	// In real implementation, this would use LWE partial decryption
	partialBytes, err := ct.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ciphertext: %w", err)
	}

	share := &DecryptionShare{
		PartyID:        p.config.PartyID,
		Index:          p.config.SecretKeyShare.Index,
		Generation:     p.config.Generation,
		CiphertextHash: ctHash,
		PartialResult:  partialBytes, // Simplified; real impl does partial decryption
	}

	return share, nil
}

// AddDecryptionShare adds a decryption share from another party.
func (p *Protocol) AddDecryptionShare(share *DecryptionShare) error {
	p.sharesMu.Lock()
	defer p.sharesMu.Unlock()

	if share.Generation != p.config.Generation {
		return ErrKeyMismatch
	}

	p.shares[share.PartyID] = share
	return nil
}

// ShareCount returns the number of collected shares.
func (p *Protocol) ShareCount() int {
	p.sharesMu.Lock()
	defer p.sharesMu.Unlock()
	return len(p.shares)
}

// CanDecrypt returns true if enough shares have been collected.
func (p *Protocol) CanDecrypt() bool {
	return p.ShareCount() >= p.config.Threshold
}

// CombineShares combines collected shares to produce the final decryption.
// Requires at least threshold shares to be collected.
//
// UNSAFE: this is NOT a real combine. Partial shares are IGNORED; the routine
// runs single-party decrypt against the full master key copy stored on every
// party. Panics unless LUX_ALLOW_FAKE_TFHE_FOR_TESTING_ONLY=1.
func (p *Protocol) CombineShares(ctx context.Context, ct *fhe.BitCiphertext) ([]byte, error) {
	guardUnsafe()
	p.sharesMu.Lock()
	defer p.sharesMu.Unlock()

	if len(p.shares) < p.config.Threshold {
		return nil, fmt.Errorf("%w: have %d, need %d", ErrInsufficientShares, len(p.shares), p.config.Threshold)
	}

	// Combine shares using Lagrange interpolation
	// Real implementation: Sum partial decryptions with Lagrange coefficients
	ctHash := computeCiphertextHash(ct)

	// Verify all shares are for the same ciphertext
	for _, share := range p.shares {
		if share.CiphertextHash != ctHash {
			return nil, fmt.Errorf("share from %s is for different ciphertext", share.PartyID)
		}
	}

	// Use direct decryption for now (simplified)
	// In production, this combines partial decryptions
	value := p.decryptor.DecryptUint64(ct)

	// Convert uint64 to bytes
	plaintext := make([]byte, 8)
	for i := 0; i < 8; i++ {
		plaintext[i] = byte(value >> (8 * i))
	}

	// Clear shares after successful decryption
	p.shares = make(map[party.ID]*DecryptionShare)

	return plaintext, nil
}

// ClearShares removes all collected shares.
func (p *Protocol) ClearShares() {
	p.sharesMu.Lock()
	defer p.sharesMu.Unlock()
	p.shares = make(map[party.ID]*DecryptionShare)
}

// RandomBit generates a threshold random encrypted bit using T-Chain.
func (p *Protocol) RandomBit(ctx context.Context, seed []byte) (*fhe.Ciphertext, error) {
	if p.thresholdRNG == nil {
		return nil, ErrThresholdNetworkUnavailable
	}
	return p.thresholdRNG.RandomBit(ctx, seed)
}

// RandomUint generates a threshold random encrypted integer using T-Chain.
func (p *Protocol) RandomUint(ctx context.Context, t fhe.FheUintType, seed []byte) (*fhe.BitCiphertext, error) {
	if p.thresholdRNG == nil {
		return nil, ErrThresholdNetworkUnavailable
	}
	return p.thresholdRNG.RandomUint(ctx, t, seed)
}

// IsThresholdNetworkAvailable checks if T-Chain is reachable.
func (p *Protocol) IsThresholdNetworkAvailable(ctx context.Context) bool {
	if p.thresholdRNG == nil {
		return false
	}
	return p.thresholdRNG.IsThresholdAvailable(ctx)
}

// GetEncryptor returns the FHE encryptor for this party.
func (p *Protocol) GetEncryptor() *fhe.BitwiseEncryptor {
	return p.encryptor
}

// GetDecryptor returns the FHE decryptor for this party.
func (p *Protocol) GetDecryptor() *fhe.BitwiseDecryptor {
	return p.decryptor
}

// GetEvaluator returns the FHE evaluator for homomorphic operations.
func (p *Protocol) GetEvaluator() *fhe.BitwiseEvaluator {
	return p.evaluator
}

// SetEvaluator sets the FHE evaluator.
func (p *Protocol) SetEvaluator(eval *fhe.BitwiseEvaluator) {
	p.evaluator = eval
}

// computeCiphertextHash computes a hash of a ciphertext for identification.
func computeCiphertextHash(ct *fhe.BitCiphertext) [32]byte {
	data, _ := ct.MarshalBinary()
	var hash [32]byte
	// Use first 32 bytes as simplified hash
	if len(data) >= 32 {
		copy(hash[:], data[:32])
	}
	return hash
}

// KeyGenerator generates threshold FHE keys using the party framework.
type KeyGenerator struct {
	threshold    int
	totalParties int
	params       fhe.Parameters
	pool         *pool.Pool
}

// NewKeyGenerator creates a new threshold FHE key generator.
func NewKeyGenerator(threshold, totalParties int, params fhe.Parameters, pl *pool.Pool) (*KeyGenerator, error) {
	if threshold < 1 {
		return nil, fmt.Errorf("threshold must be at least 1, got %d", threshold)
	}
	if totalParties < threshold {
		return nil, fmt.Errorf("totalParties (%d) must be >= threshold (%d)", totalParties, threshold)
	}

	return &KeyGenerator{
		threshold:    threshold,
		totalParties: totalParties,
		params:       params,
		pool:         pl,
	}, nil
}

// GenerateKeys generates threshold FHE keys using a trusted dealer.
// Returns the collective public key and secret key shares for each party.
//
// UNSAFE: every party gets the FULL master key — this is master-key replication,
// NOT Shamir secret sharing. Panics unless LUX_ALLOW_FAKE_TFHE_FOR_TESTING_ONLY=1.
func (kg *KeyGenerator) GenerateKeys(ctx context.Context, parties []party.ID) (*fhe.PublicKey, map[party.ID]*SecretKeyShare, error) {
	guardUnsafe()
	if len(parties) != kg.totalParties {
		return nil, nil, fmt.Errorf("expected %d parties, got %d", kg.totalParties, len(parties))
	}

	// Use fhe.KeyGenerator to create the master key
	fheKeyGen := fhe.NewKeyGenerator(kg.params)
	masterSK, masterPK := fheKeyGen.GenKeyPair()

	// Create Shamir shares of the secret key
	shares := make(map[party.ID]*SecretKeyShare)
	for i, pid := range parties {
		// In real implementation, each share would be a polynomial evaluation
		// For now, each party gets the full key (simplified for testing)
		shares[pid] = &SecretKeyShare{
			PartyID:       pid,
			Index:         i,
			Generation:    1,
			UnderlyingKey: masterSK,
			LambdaCoeff:   computeLagrangeCoeff(i, kg.totalParties),
		}
	}

	return masterPK, shares, nil
}

// computeLagrangeCoeff computes the Lagrange coefficient for party i.
func computeLagrangeCoeff(i, n int) []byte {
	// Simplified; real implementation uses proper polynomial interpolation
	coeff := make([]byte, 32)
	coeff[0] = byte(i + 1)
	return coeff
}

// Re-export key types from fhe for convenience
type (
	// Parameters is an alias for fhe.Parameters.
	Parameters = fhe.Parameters

	// ParametersLiteral is an alias for fhe.ParametersLiteral.
	ParametersLiteral = fhe.ParametersLiteral

	// Ciphertext is an alias for fhe.Ciphertext.
	Ciphertext = fhe.Ciphertext

	// BitCiphertext is an alias for fhe.BitCiphertext.
	BitCiphertext = fhe.BitCiphertext

	// FheUintType is an alias for fhe.FheUintType.
	FheUintType = fhe.FheUintType

	// ThresholdRNGProvider is an alias for fhe.ThresholdRNGProvider.
	ThresholdRNGProvider = fhe.ThresholdRNGProvider
)

// Re-export standard parameter sets from fhe
var (
	PN10QP27       = fhe.PN10QP27
	PN11QP54       = fhe.PN11QP54
	PN9QP28_STD128 = fhe.PN9QP28_STD128
)

// Re-export FHE integer types
const (
	FheUint4   = fhe.FheUint4
	FheUint8   = fhe.FheUint8
	FheUint16  = fhe.FheUint16
	FheUint32  = fhe.FheUint32
	FheUint64  = fhe.FheUint64
	FheUint128 = fhe.FheUint128
	FheUint160 = fhe.FheUint160
	FheUint256 = fhe.FheUint256
)

// NewParametersFromLiteral creates FHE parameters from a literal.
var NewParametersFromLiteral = fhe.NewParametersFromLiteral

// CalculateThreshold returns the minimum threshold for a given percentage.
var CalculateThreshold = fhe.CalculateThreshold
