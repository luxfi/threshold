// Package tfhe provides the HIGH-LEVEL orchestration layer for real
// Threshold Fully Homomorphic Encryption (M-of-N TFHE) on top of
// github.com/luxfi/fhe's LWE-based bit ciphertexts.
//
// Security model:
//
//   - The master FHE secret key is Shamir-split coefficient-by-coefficient
//     over the LWE field Z_q at keygen time. After keygen, no party — not
//     even the dealer — holds a copy of the master key. Each party j keeps
//     only its share s_j (a polynomial in R_q in coefficient form).
//
//   - To decrypt an LWE ciphertext (c_0, c_1), each chosen committee
//     member computes a partial decryption d_j = c_1·s_j + e_j, where
//     e_j is a fresh discrete-Gaussian "smudging" noise sampled wide
//     enough to mask the share contribution (the AJLTV12 / MTBH20
//     noise-flooding argument). The share s_j stays local; only d_j
//     crosses the wire.
//
//   - Any ≥ t partial decryptions can be Lagrange-interpolated to recover
//     the plaintext bit via the Bendlin-Damgård denominator-clearing
//     scheme (TCC 2010, §4.2): the combiner sums Λ_j·d_j with integer
//     Lagrange numerators and divides by Δ = total! mod q at the end.
//     The reconstruction yields the plaintext exactly, up to a noise
//     term whose magnitude is parameter-set-bounded (Q/16) and rounds
//     to the correct bit.
//
//   - Any subset of size < t recovers nothing: the secret-sharing
//     polynomial is (t-1)-private. The partial decryptions of any t-1
//     parties are simulatable from a fresh encryption of the same
//     plaintext under the master key — this is the noise-flooding
//     simulation argument and is the basis of the t-resilient security
//     proof.
//
// Decomplecting note: this file is the orchestration / committee state
// layer only. The cryptographic primitives — Shamir share of the LWE
// secret key, partial decryption, combine — live in github.com/luxfi/fhe/
// pkg/threshold. Nothing here re-implements lattice arithmetic or noise
// sampling; we orchestrate, the primitive package computes.
//
// References:
//   - Asharov, Jain, López-Alt, Tromer, Vaikuntanathan, Wichs.
//     "Multiparty Computation with Low Communication, Computation and
//     Interaction via Threshold FHE." EUROCRYPT 2012. ePrint 2011/613.
//   - Bendlin, Damgård. "Threshold Decryption and Zero-Knowledge Proofs
//     for Lattice-Based Cryptosystems." TCC 2010. (Integer Lagrange.)
//   - Mouchet, Troncoso-Pastoriza, Bossuat, Hubaux. "Multiparty
//     Homomorphic Encryption from Ring-Learning-with-Errors." PETS 2021.
//
// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause
package tfhe

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/luxfi/fhe"
	fhethreshold "github.com/luxfi/fhe/pkg/threshold"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
)

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

// Config holds the threshold FHE configuration for a single party.
//
// SECURITY: SecretKeyShare must contain a fhethreshold.LWEShare — a true
// Shamir share of the master LWE secret. The Config DOES NOT carry any
// reference to the master secret key. A party's Protocol instance cannot
// derive the master from its own state, and cannot derive any other
// party's share.
type Config struct {
	// Threshold is t in t-of-n (minimum partial decryptions needed).
	Threshold int

	// TotalParties is n in t-of-n.
	TotalParties int

	// PartyID identifies this party.
	PartyID party.ID

	// Generation is the key generation epoch (increments on key refresh).
	Generation uint64

	// FHEParams are the underlying FHE parameters.
	FHEParams fhe.Parameters

	// PublicKey is the collective FHE public key. All parties hold
	// the same public key — it is *not* secret.
	PublicKey *fhe.PublicKey

	// SecretKeyShare is this party's share of the secret key.
	SecretKeyShare *SecretKeyShare
}

// SecretKeyShare represents a single party's Shamir share of the FHE
// secret key. It carries the lattice-domain partial-decrypt share from
// fhe/pkg/threshold — never the master key itself.
type SecretKeyShare struct {
	// PartyID identifies the share owner.
	PartyID party.ID

	// Index is the share's Shamir x-coordinate (1-based; mirrors LWEShare.Index).
	Index int

	// Generation is the key generation epoch.
	Generation uint64

	// LWE is the underlying lattice partial-decrypt share. SECURITY:
	// this is *NOT* a copy of the master *fhe.SecretKey; it is the
	// per-party Shamir share computed by fhethreshold.ShareLWESecretKey.
	LWE fhethreshold.LWEShare
}

// DecryptionShare is one party's partial decryption of a specific
// ciphertext. PartialResult carries the lattice-domain partial decryption
// produced by fhethreshold.PartialDecryptLWE.
type DecryptionShare struct {
	// PartyID identifies the share creator.
	PartyID party.ID

	// Index is the Shamir x-coordinate of the contributing share.
	Index int

	// Generation is the key generation epoch.
	Generation uint64

	// CiphertextHash identifies which ciphertext this decrypts.
	CiphertextHash [32]byte

	// PartialResult is the per-bit partial decryption set: one entry per
	// bit of the originating BitCiphertext. For a single *fhe.Ciphertext,
	// PartialResult contains exactly one element.
	PartialResult []*fhethreshold.LWEPartialDecryption
}

// Protocol orchestrates threshold FHE operations for one party.
//
// SECURITY: Protocol holds the party's LWE share via Config.SecretKeyShare.
// It never materialises the master secret. Encryptor / Decryptor / Evaluator
// derived from Config use the *public* key (where applicable); no master-
// key encryptor or decryptor is constructed.
type Protocol struct {
	config *Config
	pool   *pool.Pool

	// Public-key encryptor for parties that need to encrypt without
	// holding a secret share. Backed by config.PublicKey.
	publicEncryptor *fhe.BitwisePublicEncryptor

	// Threshold RNG using T-Chain.
	thresholdRNG *fhe.ThresholdRNG

	// Collected decryption shares for the current ciphertext.
	shares   map[party.ID]*DecryptionShare
	sharesMu sync.Mutex
}

// NewProtocol creates a new threshold FHE protocol instance.
//
// SECURITY contract: config.SecretKeyShare must be a true Shamir share
// (from KeyGenerator.GenerateKeys). Passing a hand-rolled SecretKeyShare
// containing a copy of the master key is detected by the LWE primitive
// layer at first PartialDecrypt — the resulting partial-decrypt would
// not Lagrange-combine to the correct plaintext.
func NewProtocol(config *Config, pl *pool.Pool) (*Protocol, error) {
	if config == nil {
		return nil, ErrNotInitialized
	}
	if config.SecretKeyShare == nil {
		return nil, fmt.Errorf("tfhe: config.SecretKeyShare is required")
	}
	if config.PublicKey == nil {
		return nil, fmt.Errorf("tfhe: config.PublicKey is required")
	}

	p := &Protocol{
		config:          config,
		pool:            pl,
		publicEncryptor: fhe.NewBitwisePublicEncryptor(config.FHEParams, config.PublicKey),
		shares:          make(map[party.ID]*DecryptionShare),
	}

	return p, nil
}

// SetThresholdRNG sets the threshold RNG provider for this protocol.
// Connects to the T-Chain for threshold randomness.
//
// NOTE: ThresholdRNG construction still requires a master-key signature
// in the underlying luxfi/fhe API for legacy reasons. Until that API is
// updated to accept a partial-decrypt config, threshold RNG callers must
// also provide a dealer-time *fhe.SecretKey. This is a narrow exception
// to the no-master-key invariant and is gated behind the explicit
// SetThresholdRNGWithMaster method. The default SetThresholdRNG path
// returns an error if invoked before SetThresholdRNGWithMaster.
//
// TODO(luxfi/fhe#TBD): port ThresholdRNG to accept a share-based config.
func (p *Protocol) SetThresholdRNG(provider fhe.ThresholdRNGProvider) error {
	if p.thresholdRNG == nil {
		return fmt.Errorf("tfhe: threshold RNG requires SetThresholdRNGWithMaster (luxfi/fhe legacy API)")
	}
	_ = provider
	return nil
}

// SetThresholdRNGWithMaster wires the threshold RNG with a dealer-supplied
// master key. ONLY used during the initial dealer ceremony — never in
// production after key shares have been distributed.
func (p *Protocol) SetThresholdRNGWithMaster(provider fhe.ThresholdRNGProvider, masterSK *fhe.SecretKey) {
	rngConfig := &fhe.ThresholdRNGConfig{
		Provider:        provider,
		FallbackEnabled: true,
	}
	p.thresholdRNG = fhe.NewThresholdRNG(
		p.config.FHEParams,
		masterSK,
		p.config.PublicKey,
		rngConfig,
	)
}

// CreateDecryptionShare creates a partial decryption share for a
// BitCiphertext (one partial per bit). The share is bound to the
// originating ciphertext via a hash that combine() will check.
func (p *Protocol) CreateDecryptionShare(ctx context.Context, ct *fhe.BitCiphertext) (*DecryptionShare, error) {
	if ct == nil {
		return nil, fmt.Errorf("tfhe: nil ciphertext")
	}

	bits := ct.Bits()
	partials := make([]*fhethreshold.LWEPartialDecryption, len(bits))
	for i, bit := range bits {
		prng, err := sampling.NewPRNG()
		if err != nil {
			return nil, fmt.Errorf("tfhe: prng for bit %d: %w", i, err)
		}
		partial, err := fhethreshold.PartialDecryptFHE(
			&p.config.SecretKeyShare.LWE,
			bit,
			p.config.FHEParams,
			p.config.Threshold,
			prng,
		)
		if err != nil {
			return nil, fmt.Errorf("tfhe: partial decrypt bit %d: %w", i, err)
		}
		partials[i] = partial
	}

	ctHash, err := bitCiphertextHash(ct)
	if err != nil {
		return nil, fmt.Errorf("tfhe: hash ciphertext: %w", err)
	}

	return &DecryptionShare{
		PartyID:        p.config.PartyID,
		Index:          p.config.SecretKeyShare.Index,
		Generation:     p.config.Generation,
		CiphertextHash: ctHash,
		PartialResult:  partials,
	}, nil
}

// CreateBitDecryptionShare creates a partial decryption share for a
// single bit ciphertext. Useful for callers that operate on individual
// bits (e.g., the FChain 1-bit verdict path).
func (p *Protocol) CreateBitDecryptionShare(ctx context.Context, ct *fhe.Ciphertext) (*DecryptionShare, error) {
	if ct == nil {
		return nil, fmt.Errorf("tfhe: nil ciphertext")
	}
	prng, err := sampling.NewPRNG()
	if err != nil {
		return nil, fmt.Errorf("tfhe: prng: %w", err)
	}
	partial, err := fhethreshold.PartialDecryptFHE(
		&p.config.SecretKeyShare.LWE,
		ct,
		p.config.FHEParams,
		p.config.Threshold,
		prng,
	)
	if err != nil {
		return nil, fmt.Errorf("tfhe: partial decrypt: %w", err)
	}

	ctHash, err := bitCiphertextHash(fhe.WrapBoolCiphertext(ct))
	if err != nil {
		return nil, fmt.Errorf("tfhe: hash: %w", err)
	}

	return &DecryptionShare{
		PartyID:        p.config.PartyID,
		Index:          p.config.SecretKeyShare.Index,
		Generation:     p.config.Generation,
		CiphertextHash: ctHash,
		PartialResult:  []*fhethreshold.LWEPartialDecryption{partial},
	}, nil
}

// AddDecryptionShare adds a decryption share from another party.
func (p *Protocol) AddDecryptionShare(share *DecryptionShare) error {
	if share == nil {
		return fmt.Errorf("tfhe: nil share")
	}
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

// CombineShares combines collected partial decryptions and returns the
// recovered plaintext for the supplied BitCiphertext. Requires at least
// `Config.Threshold` shares; extra shares are tolerated but only the
// first t are used. The originating ciphertext's hash must match every
// collected share — caller is expected to call ClearShares between
// different ciphertexts.
func (p *Protocol) CombineShares(ctx context.Context, ct *fhe.BitCiphertext) ([]byte, error) {
	if ct == nil {
		return nil, fmt.Errorf("tfhe: nil ciphertext")
	}
	p.sharesMu.Lock()
	defer p.sharesMu.Unlock()

	if len(p.shares) < p.config.Threshold {
		return nil, fmt.Errorf("%w: have %d, need %d", ErrInsufficientShares, len(p.shares), p.config.Threshold)
	}

	ctHash, err := bitCiphertextHash(ct)
	if err != nil {
		return nil, fmt.Errorf("tfhe: hash ciphertext: %w", err)
	}

	// Verify all shares are for the same ciphertext.
	for _, s := range p.shares {
		if s.CiphertextHash != ctHash {
			return nil, fmt.Errorf("tfhe: share from %s is for a different ciphertext", s.PartyID)
		}
	}

	// Pick exactly p.config.Threshold shares from those collected.
	// We use insertion order; iteration order is random in Go but the
	// combine is invariant under share order, so this is fine.
	picked := make([]*DecryptionShare, 0, p.config.Threshold)
	for _, s := range p.shares {
		picked = append(picked, s)
		if len(picked) == p.config.Threshold {
			break
		}
	}

	// Combine per-bit: each bit gets its own t-of-n threshold decryption.
	bits := ct.Bits()
	plaintextBits := make([]byte, len(bits))
	for i, bit := range bits {
		partials := make([]*fhethreshold.LWEPartialDecryption, len(picked))
		for j, s := range picked {
			if i >= len(s.PartialResult) {
				return nil, fmt.Errorf("tfhe: share from %s missing partial for bit %d", s.PartyID, i)
			}
			partials[j] = s.PartialResult[i]
		}
		decoded, err := fhethreshold.CombineFHE(bit, partials, p.config.FHEParams)
		if err != nil {
			return nil, fmt.Errorf("tfhe: combine bit %d: %w", i, err)
		}
		if decoded {
			plaintextBits[i] = 1
		}
	}

	// Pack bits into bytes (LSB first within each byte, matches
	// BitwiseDecryptor's natural layout).
	out := make([]byte, (len(plaintextBits)+7)/8)
	for i, bit := range plaintextBits {
		if bit == 1 {
			out[i/8] |= 1 << uint(i%8)
		}
	}

	// Clear shares for the next ciphertext.
	p.shares = make(map[party.ID]*DecryptionShare)

	return out, nil
}

// CombineBitShares combines collected partial decryptions for a single
// bit ciphertext, returning the recovered bit.
func (p *Protocol) CombineBitShares(ctx context.Context, ct *fhe.Ciphertext) (bool, error) {
	if ct == nil {
		return false, fmt.Errorf("tfhe: nil ciphertext")
	}
	p.sharesMu.Lock()
	defer p.sharesMu.Unlock()

	if len(p.shares) < p.config.Threshold {
		return false, fmt.Errorf("%w: have %d, need %d", ErrInsufficientShares, len(p.shares), p.config.Threshold)
	}

	wrapped := fhe.WrapBoolCiphertext(ct)
	ctHash, err := bitCiphertextHash(wrapped)
	if err != nil {
		return false, fmt.Errorf("tfhe: hash: %w", err)
	}
	for _, s := range p.shares {
		if s.CiphertextHash != ctHash {
			return false, fmt.Errorf("tfhe: share from %s is for a different ciphertext", s.PartyID)
		}
	}

	picked := make([]*DecryptionShare, 0, p.config.Threshold)
	for _, s := range p.shares {
		picked = append(picked, s)
		if len(picked) == p.config.Threshold {
			break
		}
	}

	partials := make([]*fhethreshold.LWEPartialDecryption, len(picked))
	for j, s := range picked {
		if len(s.PartialResult) != 1 {
			return false, fmt.Errorf("tfhe: share from %s has %d partials, expected 1", s.PartyID, len(s.PartialResult))
		}
		partials[j] = s.PartialResult[0]
	}

	decoded, err := fhethreshold.CombineFHE(ct, partials, p.config.FHEParams)
	if err != nil {
		return false, fmt.Errorf("tfhe: combine: %w", err)
	}

	p.shares = make(map[party.ID]*DecryptionShare)
	return decoded, nil
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

// PublicEncryptor returns the public-key encryptor for this party. Any
// party can encrypt — no secret share needed.
func (p *Protocol) PublicEncryptor() *fhe.BitwisePublicEncryptor {
	return p.publicEncryptor
}

// SecretShareIndex returns this party's Shamir x-coordinate.
func (p *Protocol) SecretShareIndex() int {
	return p.config.SecretKeyShare.Index
}

// KeyGenerator generates threshold FHE keys via Shamir-based dealing.
//
// CURRENT IMPLEMENTATION: trusted-dealer ceremony. The dealer briefly
// holds the master secret long enough to Shamir-split it, distributes
// shares to each party, and is then expected to wipe the master. The
// dealer is in the trust boundary for keygen only — after keygen, no
// party (including the dealer) can decrypt without the threshold.
//
// FUTURE: replace with distributed key generation (RLWE-DKG) so the
// master key is never materialised in one place. The committee
// dispatch surface (Protocol.CreateDecryptionShare / CombineShares) is
// unchanged by that upgrade — only KeyGenerator changes.
type KeyGenerator struct {
	threshold    int
	totalParties int
	params       fhe.Parameters
	pool         *pool.Pool
}

// NewKeyGenerator creates a new threshold FHE key generator.
func NewKeyGenerator(threshold, totalParties int, params fhe.Parameters, pl *pool.Pool) (*KeyGenerator, error) {
	if threshold < 1 {
		return nil, fmt.Errorf("tfhe: threshold must be at least 1, got %d", threshold)
	}
	if totalParties < threshold {
		return nil, fmt.Errorf("tfhe: totalParties (%d) must be >= threshold (%d)", totalParties, threshold)
	}

	return &KeyGenerator{
		threshold:    threshold,
		totalParties: totalParties,
		params:       params,
		pool:         pl,
	}, nil
}

// GenerateKeys runs the trusted-dealer keygen ceremony.
//
// Pipeline:
//
//  1. Generate the master LWE secret key locally (dealer).
//  2. Derive the collective public key from the master (same public key
//     for all parties — public keys are not secret).
//  3. Shamir-split the master into per-party LWE shares via
//     fhethreshold.ShareLWESecretKeyFHE.
//  4. Wipe the master from local memory and return shares + public key.
//
// The dealer is in the trust boundary only for step 1-3. After return,
// the dealer holds the public key (not secret) and no share.
func (kg *KeyGenerator) GenerateKeys(ctx context.Context, parties []party.ID) (*fhe.PublicKey, map[party.ID]*SecretKeyShare, error) {
	if len(parties) != kg.totalParties {
		return nil, nil, fmt.Errorf("tfhe: expected %d parties, got %d", kg.totalParties, len(parties))
	}

	// 1) Master keygen.
	fheKeyGen := fhe.NewKeyGenerator(kg.params)
	masterSK, masterPK := fheKeyGen.GenKeyPair()

	// 2) Shamir-split. Parties get LWE shares, not master copies.
	lweShares, err := fhethreshold.ShareLWESecretKeyFHE(masterSK, kg.params, kg.threshold, kg.totalParties)
	if err != nil {
		return nil, nil, fmt.Errorf("tfhe: share LWE secret key: %w", err)
	}
	if len(lweShares) != kg.totalParties {
		return nil, nil, fmt.Errorf("tfhe: share count mismatch: got %d want %d", len(lweShares), kg.totalParties)
	}

	// 3) Bind shares to party IDs.
	shares := make(map[party.ID]*SecretKeyShare, kg.totalParties)
	for i, pid := range parties {
		shares[pid] = &SecretKeyShare{
			PartyID:    pid,
			Index:      lweShares[i].Index,
			Generation: 1,
			LWE:        lweShares[i],
		}
	}

	// 4) Wipe the master secret. We can only clear its standard-form
	//    LWE polynomial; the BR (blind-rotation) secret key is not used
	//    by threshold decrypt — it's only relevant during evaluation,
	//    which still requires the bootstrap key (which is public by
	//    construction in luxfi/fhe). For threshold operation we never
	//    need masterSK again.
	if masterSK.SKLWE != nil {
		masterSK.SKLWE.Value.Q.Zero()
		if masterSK.SKLWE.Value.P.N() > 0 {
			masterSK.SKLWE.Value.P.Zero()
		}
	}

	return masterPK, shares, nil
}

// GenerateKeysWithMaster is identical to GenerateKeys but returns the
// master secret key in addition to the shares. ONLY used for tests and
// for the legacy ThresholdRNG path that still requires a master. The
// caller is expected to wipe the master after consuming it.
//
// Production code paths must use GenerateKeys, not this.
func (kg *KeyGenerator) GenerateKeysWithMaster(ctx context.Context, parties []party.ID) (*fhe.SecretKey, *fhe.PublicKey, map[party.ID]*SecretKeyShare, error) {
	if len(parties) != kg.totalParties {
		return nil, nil, nil, fmt.Errorf("tfhe: expected %d parties, got %d", kg.totalParties, len(parties))
	}
	fheKeyGen := fhe.NewKeyGenerator(kg.params)
	masterSK, masterPK := fheKeyGen.GenKeyPair()

	lweShares, err := fhethreshold.ShareLWESecretKeyFHE(masterSK, kg.params, kg.threshold, kg.totalParties)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("tfhe: share LWE secret key: %w", err)
	}

	shares := make(map[party.ID]*SecretKeyShare, kg.totalParties)
	for i, pid := range parties {
		shares[pid] = &SecretKeyShare{
			PartyID:    pid,
			Index:      lweShares[i].Index,
			Generation: 1,
			LWE:        lweShares[i],
		}
	}

	return masterSK, masterPK, shares, nil
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

// CalculateThreshold returns the minimum threshold for a given party count.
var CalculateThreshold = fhe.CalculateThreshold
