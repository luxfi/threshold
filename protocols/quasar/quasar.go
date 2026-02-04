// Package quasar provides hybrid threshold signatures combining BLS (elliptic curve)
// with Ringtail (post-quantum lattice-based) for security against both classical
// and quantum computer attacks.
//
// Quasar signatures are "quantum-safe and reliable" - they provide:
//   - Immediate security via BLS12-381 pairing-based signatures
//   - Future-proof post-quantum security via Ringtail (Module-LWE)
//   - Threshold signing: t-of-n parties required to produce valid signatures
//   - Flexible verification: verify both components, BLS-only, or Ringtail-only
//
// Usage:
//
//	// Generate keys for 3 parties with threshold 2
//	dealer := &quasar.TrustedDealer{Threshold: 2, TotalParties: 3}
//	shares, err := dealer.GenerateShares(ctx, partyIDs)
//
//	// Each party signs
//	proto := quasar.NewProtocol(shares[myID])
//	share, _ := proto.Sign(ctx, message, sessionID, prfKey, signerList)
//
//	// Collect shares and finalize
//	proto.AddShare(theirShare)
//	sig, _ := proto.Finalize(message)
//
//	// Verify (both BLS and Ringtail)
//	valid := quasar.Verify(groupKey, message, sig)
package quasar

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/ringtail/threshold"
	"github.com/luxfi/threshold/pkg/party"
	blsThreshold "github.com/luxfi/threshold/protocols/bls"
)

var (
	// ErrNotInitialized is returned when operations are attempted before setup.
	ErrNotInitialized = errors.New("quasar: not initialized")

	// ErrRingtailFailed is returned when the post-quantum component fails.
	ErrRingtailFailed = errors.New("quasar: ringtail component failed")

	// ErrBLSFailed is returned when the BLS component fails.
	ErrBLSFailed = errors.New("quasar: BLS component failed")

	// ErrInsufficientShares is returned when not enough shares are collected.
	ErrInsufficientShares = errors.New("quasar: insufficient shares for threshold")

	// ErrVerificationFailed is returned when signature verification fails.
	ErrVerificationFailed = errors.New("quasar: verification failed")
)

// Config holds configuration for a Quasar threshold signing participant.
type Config struct {
	// ID is this party's identifier
	ID party.ID

	// Threshold is the minimum number of parties needed to sign (t in t-of-n)
	Threshold int

	// TotalParties is n in t-of-n
	TotalParties int

	// BLS configuration
	BLSSecretShare *bls.SecretKey
	BLSPublicKey   *bls.PublicKey
	BLSVerifyKeys  map[party.ID]*bls.PublicKey

	// Ringtail (post-quantum) configuration
	RingtailShare    *threshold.KeyShare
	RingtailGroupKey *threshold.GroupKey
}

// GroupKey represents the combined public key for Quasar verification.
type GroupKey struct {
	// BLS aggregate public key
	BLS *bls.PublicKey

	// Ringtail group public key
	Ringtail *threshold.GroupKey
}

// Bytes returns a serialized representation of the group key.
func (gk *GroupKey) Bytes() []byte {
	if gk == nil {
		return nil
	}
	result := make([]byte, 0)
	if gk.BLS != nil {
		result = append(result, bls.PublicKeyToCompressedBytes(gk.BLS)...)
	}
	if gk.Ringtail != nil {
		result = append(result, gk.Ringtail.Bytes()...)
	}
	return result
}

// SignatureShare represents a party's contribution to a Quasar signature.
type SignatureShare struct {
	PartyID party.ID

	// BLS component (elliptic curve)
	BLSShare *blsThreshold.SignatureShare

	// Ringtail components (post-quantum lattice)
	RingtailRound1 *threshold.Round1Data
	RingtailRound2 *threshold.Round2Data
}

// Signature represents a complete Quasar hybrid signature.
// For full security, verifiers should check BOTH components.
type Signature struct {
	// BLS signature (96 bytes compressed G2 point)
	BLS *bls.Signature

	// Ringtail signature (post-quantum lattice-based)
	Ringtail *threshold.Signature

	// MessageHash binds the signature to a specific message
	MessageHash []byte
}

// HasRingtail returns true if the signature includes a post-quantum component.
func (s *Signature) HasRingtail() bool {
	return s != nil && s.Ringtail != nil
}

// HasBLS returns true if the signature includes a BLS component.
func (s *Signature) HasBLS() bool {
	return s != nil && s.BLS != nil
}

// Bytes serializes the Quasar signature.
// Format: [1-byte flags][BLS sig][optional Ringtail sig]
func (s *Signature) Bytes() ([]byte, error) {
	if s == nil || s.BLS == nil {
		return nil, ErrNotInitialized
	}

	blsBytes := bls.SignatureToBytes(s.BLS)

	var flags byte = 0x00
	if s.Ringtail != nil {
		flags |= 0x01 // Ringtail present
	}

	result := make([]byte, 1+len(blsBytes))
	result[0] = flags
	copy(result[1:], blsBytes)

	// TODO: Append Ringtail serialization when present
	return result, nil
}

// Protocol orchestrates Quasar hybrid threshold signing.
type Protocol struct {
	config *Config
	mu     sync.Mutex

	// BLS threshold protocol
	blsConfig *blsThreshold.Config

	// Ringtail signer (post-quantum)
	ringtailSigner *threshold.Signer
	signers        []int

	// Collected shares
	blsShares      map[party.ID]*blsThreshold.SignatureShare
	ringtailRound1 map[int]*threshold.Round1Data
	ringtailRound2 map[int]*threshold.Round2Data
}

// NewProtocol creates a new Quasar signing protocol instance.
func NewProtocol(config *Config) (*Protocol, error) {
	if config == nil {
		return nil, ErrNotInitialized
	}
	if config.BLSSecretShare == nil {
		return nil, fmt.Errorf("%w: BLS secret share required", ErrNotInitialized)
	}

	// Create BLS threshold config
	blsConfig := blsThreshold.NewConfig(
		config.ID,
		config.Threshold,
		config.TotalParties,
		config.BLSSecretShare,
		config.BLSPublicKey,
		config.BLSVerifyKeys,
	)

	// Create Ringtail signer if configured
	var ringtailSigner *threshold.Signer
	if config.RingtailShare != nil {
		ringtailSigner = threshold.NewSigner(config.RingtailShare)
	}

	return &Protocol{
		config:         config,
		blsConfig:      blsConfig,
		ringtailSigner: ringtailSigner,
		blsShares:      make(map[party.ID]*blsThreshold.SignatureShare),
		ringtailRound1: make(map[int]*threshold.Round1Data),
		ringtailRound2: make(map[int]*threshold.Round2Data),
	}, nil
}

// Sign creates a Quasar signature share with both BLS and Ringtail components.
func (p *Protocol) Sign(ctx context.Context, message []byte, sessionID int, prfKey []byte, signerIndices []int) (*SignatureShare, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	share := &SignatureShare{
		PartyID: p.config.ID,
	}

	// Create BLS signature share
	blsShare, err := p.blsConfig.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBLSFailed, err)
	}
	share.BLSShare = blsShare

	// Create Ringtail Round 1 data if configured
	if p.ringtailSigner != nil && len(signerIndices) > 0 {
		p.signers = signerIndices
		round1 := p.ringtailSigner.Round1(sessionID, prfKey, signerIndices)
		share.RingtailRound1 = round1
	}

	return share, nil
}

// AddBLSShare adds a BLS signature share from another party.
func (p *Protocol) AddBLSShare(share *blsThreshold.SignatureShare) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.blsShares[share.PartyID] = share
}

// AddShare adds a complete signature share from another party.
func (p *Protocol) AddShare(share *SignatureShare) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if share.BLSShare != nil {
		p.blsShares[share.PartyID] = share.BLSShare
	}
	if share.RingtailRound1 != nil {
		p.ringtailRound1[share.RingtailRound1.PartyID] = share.RingtailRound1
	}
	if share.RingtailRound2 != nil {
		p.ringtailRound2[share.RingtailRound2.PartyID] = share.RingtailRound2
	}
}

// AddRingtailRound1 adds Ringtail Round 1 data from another party.
func (p *Protocol) AddRingtailRound1(data *threshold.Round1Data) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ringtailRound1[data.PartyID] = data
}

// CompleteRingtailRound2 completes Ringtail signing after Round 1 data collection.
func (p *Protocol) CompleteRingtailRound2(sessionID int, message string, prfKey []byte) (*threshold.Round2Data, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.ringtailSigner == nil {
		return nil, fmt.Errorf("%w: ringtail not configured", ErrNotInitialized)
	}

	round2, err := p.ringtailSigner.Round2(sessionID, message, prfKey, p.signers, p.ringtailRound1)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRingtailFailed, err)
	}

	return round2, nil
}

// AddRingtailRound2 adds Ringtail Round 2 data from another party.
func (p *Protocol) AddRingtailRound2(data *threshold.Round2Data) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ringtailRound2[data.PartyID] = data
}

// BLSShareCount returns the number of BLS shares collected.
func (p *Protocol) BLSShareCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.blsShares)
}

// CanFinalize returns true if enough shares are collected.
func (p *Protocol) CanFinalize() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.blsShares) >= p.config.Threshold
}

// Finalize combines all shares into the final Quasar signature.
func (p *Protocol) Finalize(message []byte) (*Signature, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check we have enough BLS shares
	if len(p.blsShares) < p.config.Threshold {
		return nil, fmt.Errorf("%w: have %d BLS, need %d",
			ErrInsufficientShares, len(p.blsShares), p.config.Threshold)
	}

	// Aggregate BLS signatures
	blsShareSlice := make([]*blsThreshold.SignatureShare, 0, len(p.blsShares))
	for _, share := range p.blsShares {
		blsShareSlice = append(blsShareSlice, share)
	}

	blsSig, err := blsThreshold.AggregateSignatures(blsShareSlice, p.config.Threshold)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBLSFailed, err)
	}

	sig := &Signature{
		BLS:         blsSig,
		MessageHash: hashMessage(message),
	}

	// Finalize Ringtail if configured and enough shares
	if p.ringtailSigner != nil && len(p.ringtailRound2) >= p.config.Threshold {
		ringtailSig, err := p.ringtailSigner.Finalize(p.ringtailRound2)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrRingtailFailed, err)
		}
		sig.Ringtail = ringtailSig
	}

	return sig, nil
}

// ClearShares resets collected shares for a new signing session.
func (p *Protocol) ClearShares() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.blsShares = make(map[party.ID]*blsThreshold.SignatureShare)
	p.ringtailRound1 = make(map[int]*threshold.Round1Data)
	p.ringtailRound2 = make(map[int]*threshold.Round2Data)
}

// Verify verifies a Quasar signature.
// For full hybrid security, both BLS and Ringtail (if present) must verify.
func Verify(groupKey *GroupKey, message []byte, sig *Signature) (bool, error) {
	if sig == nil {
		return false, errors.New("nil signature")
	}
	if groupKey == nil {
		return false, errors.New("nil group key")
	}

	// Verify BLS component (required)
	if sig.BLS == nil {
		return false, ErrBLSFailed
	}
	if !bls.Verify(groupKey.BLS, sig.BLS, message) {
		return false, nil
	}

	// Verify Ringtail component (if present)
	if sig.Ringtail != nil && groupKey.Ringtail != nil {
		if !threshold.Verify(groupKey.Ringtail, string(message), sig.Ringtail) {
			return false, nil
		}
	}

	return true, nil
}

// VerifyBLSOnly verifies only the BLS component.
// Use for fast verification when post-quantum security isn't required.
func VerifyBLSOnly(pubKey *bls.PublicKey, message []byte, sig *Signature) bool {
	if sig == nil || sig.BLS == nil || pubKey == nil {
		return false
	}
	return bls.Verify(pubKey, sig.BLS, message)
}

// VerifyRingtailOnly verifies only the Ringtail component.
// Use for quantum-resistant verification.
func VerifyRingtailOnly(groupKey *threshold.GroupKey, message string, sig *Signature) bool {
	if sig == nil || sig.Ringtail == nil || groupKey == nil {
		return false
	}
	return threshold.Verify(groupKey, message, sig.Ringtail)
}

// TrustedDealer generates Quasar key shares using a trusted dealer.
type TrustedDealer struct {
	Threshold    int
	TotalParties int
}

// GenerateShares creates Quasar key shares for all parties.
// Returns configs for each party and the combined group key.
func (d *TrustedDealer) GenerateShares(ctx context.Context, partyIDs []party.ID) (map[party.ID]*Config, *GroupKey, error) {
	if len(partyIDs) != d.TotalParties {
		return nil, nil, fmt.Errorf("party count mismatch: got %d, want %d", len(partyIDs), d.TotalParties)
	}

	// Generate BLS shares
	blsDealer := &blsThreshold.TrustedDealer{
		Threshold:    d.Threshold,
		TotalParties: d.TotalParties,
	}
	blsShares, blsGroupPK, err := blsDealer.GenerateShares(ctx, partyIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("BLS keygen failed: %w", err)
	}
	blsVerifyKeys := blsThreshold.GetVerificationKeys(blsShares)

	// Generate Ringtail shares
	ringtailShares, ringtailGroupKey, err := threshold.GenerateKeys(d.Threshold, d.TotalParties, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("Ringtail keygen failed: %w", err)
	}

	// Build configs for each party
	configs := make(map[party.ID]*Config, len(partyIDs))
	for i, id := range partyIDs {
		configs[id] = &Config{
			ID:               id,
			Threshold:        d.Threshold,
			TotalParties:     d.TotalParties,
			BLSSecretShare:   blsShares[id],
			BLSPublicKey:     blsGroupPK,
			BLSVerifyKeys:    blsVerifyKeys,
			RingtailShare:    ringtailShares[i],
			RingtailGroupKey: ringtailGroupKey,
		}
	}

	groupKey := &GroupKey{
		BLS:      blsGroupPK,
		Ringtail: ringtailGroupKey,
	}

	return configs, groupKey, nil
}

// hashMessage computes a binding hash of the message.
func hashMessage(message []byte) []byte {
	// Use XOR-based hash as placeholder
	// Production should use zeebo/blake3
	h := make([]byte, 32)
	for i, b := range message {
		h[i%32] ^= b
	}
	return h
}
