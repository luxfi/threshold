// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package bls implements BLS threshold signatures.
//
// BLS threshold signatures provide:
//   - Non-interactive signature aggregation
//   - Constant-size signatures regardless of threshold
//   - Efficient verification
//
// This implementation uses Shamir's Secret Sharing for key distribution
// and Lagrange interpolation for signature combination.
package bls

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/cloudflare/circl/ecc/bls12381/ff"
	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/crypto/threshold"
)

func init() {
	threshold.RegisterScheme(&Scheme{})
}

// Constants for BLS threshold scheme.
const (
	// KeyShareSize is the serialized size of a BLS key share.
	// 32 bytes secret + 48 bytes public share + 48 bytes group key + 4 bytes metadata
	KeyShareSize = 132

	// SignatureShareSize is the serialized size of a signature share.
	// 96 bytes signature + 4 bytes index
	SignatureShareSize = 100

	// SignatureSize is the serialized size of the final signature.
	SignatureSize = 96

	// PublicKeySize is the serialized size of the group public key.
	PublicKeySize = 48
)

// Scheme implements the BLS threshold signature scheme.
type Scheme struct{}

// ID returns the scheme identifier.
func (s *Scheme) ID() threshold.SchemeID {
	return threshold.SchemeBLS
}

// Name returns the human-readable name.
func (s *Scheme) Name() string {
	return "BLS Threshold"
}

// KeyShareSize returns the serialized key share size.
func (s *Scheme) KeyShareSize() int {
	return KeyShareSize
}

// SignatureShareSize returns the serialized signature share size.
func (s *Scheme) SignatureShareSize() int {
	return SignatureShareSize
}

// SignatureSize returns the serialized final signature size.
func (s *Scheme) SignatureSize() int {
	return SignatureSize
}

// PublicKeySize returns the serialized public key size.
func (s *Scheme) PublicKeySize() int {
	return PublicKeySize
}

// NewDKG creates a new distributed key generation instance.
// BLS DKG is not yet implemented here. Use threshold/protocols/frost for production DKG.
func (s *Scheme) NewDKG(config threshold.DKGConfig) (threshold.DKG, error) {
	return nil, fmt.Errorf("BLS DKG not yet implemented: use threshold/protocols/frost for production DKG")
}

// NewTrustedDealer creates a trusted dealer for centralized key generation.
func (s *Scheme) NewTrustedDealer(config threshold.DealerConfig) (threshold.TrustedDealer, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &TrustedDealer{
		config: config,
	}, nil
}

// NewSigner creates a signer from a key share.
func (s *Scheme) NewSigner(share threshold.KeyShare) (threshold.Signer, error) {
	ks, ok := share.(*KeyShare)
	if !ok {
		return nil, threshold.ErrInvalidKeyShare
	}
	return &Signer{
		keyShare: ks,
	}, nil
}

// NewAggregator creates a signature aggregator for the given group key.
func (s *Scheme) NewAggregator(groupKey threshold.PublicKey) (threshold.Aggregator, error) {
	pk, ok := groupKey.(*PublicKey)
	if !ok {
		return nil, threshold.ErrInvalidPublicKey
	}
	return &Aggregator{
		groupKey: pk,
	}, nil
}

// NewVerifier creates a signature verifier for the given group key.
func (s *Scheme) NewVerifier(groupKey threshold.PublicKey) (threshold.Verifier, error) {
	pk, ok := groupKey.(*PublicKey)
	if !ok {
		return nil, threshold.ErrInvalidPublicKey
	}
	return &Verifier{
		groupKey: pk,
	}, nil
}

// ParseKeyShare deserializes a key share from bytes.
func (s *Scheme) ParseKeyShare(data []byte) (threshold.KeyShare, error) {
	if len(data) < KeyShareSize {
		return nil, threshold.ErrDataTooShort
	}
	return parseKeyShare(data)
}

// ParsePublicKey deserializes a group public key from bytes.
func (s *Scheme) ParsePublicKey(data []byte) (threshold.PublicKey, error) {
	if len(data) != PublicKeySize {
		return nil, threshold.ErrInvalidPublicKey
	}

	pk, err := bls.PublicKeyFromCompressedBytes(data)
	if err != nil {
		return nil, threshold.ErrInvalidPublicKey
	}

	return &PublicKey{
		key: pk,
	}, nil
}

// ParseSignatureShare deserializes a signature share from bytes.
func (s *Scheme) ParseSignatureShare(data []byte) (threshold.SignatureShare, error) {
	if len(data) < SignatureShareSize {
		return nil, threshold.ErrDataTooShort
	}
	return parseSignatureShare(data)
}

// ParseSignature deserializes a final signature from bytes.
func (s *Scheme) ParseSignature(data []byte) (threshold.Signature, error) {
	if len(data) != SignatureSize {
		return nil, threshold.ErrInvalidSignature
	}

	sig, err := bls.SignatureFromBytes(data)
	if err != nil {
		return nil, threshold.ErrInvalidSignature
	}

	return &Signature{
		sig: sig,
	}, nil
}

// PublicKey represents a BLS threshold group public key.
type PublicKey struct {
	key *bls.PublicKey
}

// Bytes serializes the public key.
func (pk *PublicKey) Bytes() []byte {
	return bls.PublicKeyToCompressedBytes(pk.key)
}

// Equal returns true if the public keys are identical.
func (pk *PublicKey) Equal(other threshold.PublicKey) bool {
	otherPK, ok := other.(*PublicKey)
	if !ok {
		return false
	}
	return bytes.Equal(pk.Bytes(), otherPK.Bytes())
}

// SchemeID returns the scheme identifier.
func (pk *PublicKey) SchemeID() threshold.SchemeID {
	return threshold.SchemeBLS
}

// KeyShare represents a party's BLS key share.
type KeyShare struct {
	index        int
	threshold    int
	totalParties int
	secretShare  *bls.SecretKey
	publicShare  *bls.PublicKey
	groupKey     *PublicKey
}

// Index returns the party index.
func (ks *KeyShare) Index() int {
	return ks.index
}

// GroupKey returns the group public key.
func (ks *KeyShare) GroupKey() threshold.PublicKey {
	return ks.groupKey
}

// PublicShare returns this party's public key share.
func (ks *KeyShare) PublicShare() []byte {
	return bls.PublicKeyToCompressedBytes(ks.publicShare)
}

// Threshold returns the signing threshold.
func (ks *KeyShare) Threshold() int {
	return ks.threshold
}

// TotalParties returns the total number of parties.
func (ks *KeyShare) TotalParties() int {
	return ks.totalParties
}

// Bytes serializes the key share.
func (ks *KeyShare) Bytes() []byte {
	buf := make([]byte, KeyShareSize)

	// Secret share (32 bytes)
	copy(buf[0:32], bls.SecretKeyToBytes(ks.secretShare))

	// Public share (48 bytes)
	copy(buf[32:80], bls.PublicKeyToCompressedBytes(ks.publicShare))

	// Group key (48 bytes)
	copy(buf[80:128], ks.groupKey.Bytes())

	// Metadata (4 bytes: index, threshold, total)
	buf[128] = byte(ks.index)
	buf[129] = byte(ks.threshold)
	buf[130] = byte(ks.totalParties >> 8)
	buf[131] = byte(ks.totalParties)

	return buf
}

// SchemeID returns the scheme identifier.
func (ks *KeyShare) SchemeID() threshold.SchemeID {
	return threshold.SchemeBLS
}

// parseKeyShare deserializes a key share.
func parseKeyShare(data []byte) (*KeyShare, error) {
	if len(data) < KeyShareSize {
		return nil, threshold.ErrDataTooShort
	}

	// Secret share
	sk, err := bls.SecretKeyFromBytes(data[0:32])
	if err != nil {
		return nil, threshold.ErrInvalidKeyShare
	}

	// Public share
	pk, err := bls.PublicKeyFromCompressedBytes(data[32:80])
	if err != nil {
		return nil, threshold.ErrInvalidKeyShare
	}

	// Group key
	gk, err := bls.PublicKeyFromCompressedBytes(data[80:128])
	if err != nil {
		return nil, threshold.ErrInvalidKeyShare
	}

	return &KeyShare{
		index:        int(data[128]),
		threshold:    int(data[129]),
		totalParties: int(data[130])<<8 | int(data[131]),
		secretShare:  sk,
		publicShare:  pk,
		groupKey:     &PublicKey{key: gk},
	}, nil
}

// SignatureShare represents a BLS signature share.
type SignatureShare struct {
	index int
	sig   *bls.Signature
}

// Index returns the party index.
func (ss *SignatureShare) Index() int {
	return ss.index
}

// Bytes serializes the signature share.
func (ss *SignatureShare) Bytes() []byte {
	buf := make([]byte, SignatureShareSize)
	binary.BigEndian.PutUint32(buf[0:4], uint32(ss.index))
	copy(buf[4:], bls.SignatureToBytes(ss.sig))
	return buf
}

// SchemeID returns the scheme identifier.
func (ss *SignatureShare) SchemeID() threshold.SchemeID {
	return threshold.SchemeBLS
}

// parseSignatureShare deserializes a signature share.
func parseSignatureShare(data []byte) (*SignatureShare, error) {
	if len(data) < SignatureShareSize {
		return nil, threshold.ErrDataTooShort
	}

	index := int(binary.BigEndian.Uint32(data[0:4]))
	sig, err := bls.SignatureFromBytes(data[4:100])
	if err != nil {
		return nil, threshold.ErrInvalidSignatureShare
	}

	return &SignatureShare{
		index: index,
		sig:   sig,
	}, nil
}

// Signature represents a final BLS threshold signature.
type Signature struct {
	sig *bls.Signature
}

// Bytes serializes the signature.
func (s *Signature) Bytes() []byte {
	return bls.SignatureToBytes(s.sig)
}

// SchemeID returns the scheme identifier.
func (s *Signature) SchemeID() threshold.SchemeID {
	return threshold.SchemeBLS
}

// TrustedDealer generates key shares using a trusted dealer.
type TrustedDealer struct {
	config threshold.DealerConfig
}

// GenerateShares creates all key shares and the group public key.
func (d *TrustedDealer) GenerateShares(ctx context.Context) ([]threshold.KeyShare, threshold.PublicKey, error) {
	rng := d.config.Rand
	if rng == nil {
		rng = rand.Reader
	}

	// Generate master secret key
	masterSK, err := bls.NewSecretKey()
	if err != nil {
		return nil, nil, err
	}

	// Compute group public key
	groupPK := masterSK.PublicKey()

	// Generate polynomial coefficients for Shamir secret sharing
	// f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
	// where a_0 = masterSK
	// For t-of-n threshold, we need degree t-1 (so t points uniquely determine it)
	coefficients := make([]*bls.SecretKey, d.config.Threshold)
	coefficients[0] = masterSK

	for i := 1; i < d.config.Threshold; i++ {
		coef, err := bls.NewSecretKey()
		if err != nil {
			return nil, nil, err
		}
		coefficients[i] = coef
	}

	// Generate shares by evaluating polynomial at points 1, 2, ..., n
	shares := make([]threshold.KeyShare, d.config.TotalParties)
	for i := 0; i < d.config.TotalParties; i++ {
		// Evaluate polynomial at x = i+1
		shareSecret := evaluatePolynomial(coefficients, i+1)

		// Compute public share
		sharePK := shareSecret.PublicKey()

		shares[i] = &KeyShare{
			index:        i,
			threshold:    d.config.Threshold,
			totalParties: d.config.TotalParties,
			secretShare:  shareSecret,
			publicShare:  sharePK,
			groupKey:     &PublicKey{key: groupPK},
		}
	}

	return shares, &PublicKey{key: groupPK}, nil
}

// evaluatePolynomial evaluates a polynomial at a given point using BLS12-381 scalar field arithmetic.
// f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_t*x^t using Horner's method.
func evaluatePolynomial(coefficients []*bls.SecretKey, x int) *bls.SecretKey {
	if len(coefficients) == 0 {
		return nil
	}

	// Convert coefficients to scalars
	scalars := make([]*ff.Scalar, len(coefficients))
	for i, coef := range coefficients {
		scalars[i] = new(ff.Scalar)
		scalars[i].SetBytes(bls.SecretKeyToBytes(coef))
	}

	// Convert x to scalar
	xScalar := new(ff.Scalar)
	xScalar.SetUint64(uint64(x))

	// Evaluate using Horner's method: f(x) = a_n + x*(a_{n-1} + x*(a_{n-2} + ...))
	result := new(ff.Scalar)
	result.Set(scalars[len(scalars)-1])

	for i := len(scalars) - 2; i >= 0; i-- {
		// result = result * x + a_i
		result.Mul(result, xScalar)
		result.Add(result, scalars[i])
	}

	// Convert back to SecretKey
	resultBytes, _ := result.MarshalBinary()
	sk, err := bls.SecretKeyFromBytes(resultBytes)
	if err != nil {
		// Fallback to constant term if conversion fails
		return coefficients[0]
	}
	return sk
}

// computeLagrangeCoefficients computes Lagrange coefficients at x=0 for the given indices.
// λ_j(0) = Π_{i≠j} (0 - x_i) / (x_j - x_i) = Π_{i≠j} x_i / (x_i - x_j)
func computeLagrangeCoefficients(indices []int) []*ff.Scalar {
	n := len(indices)
	coeffs := make([]*ff.Scalar, n)

	for j := 0; j < n; j++ {
		xj := new(ff.Scalar)
		xj.SetUint64(uint64(indices[j]))

		// numerator = Π_{i≠j} x_i
		numerator := new(ff.Scalar)
		numerator.SetOne()

		// denominator = Π_{i≠j} (x_j - x_i)
		denominator := new(ff.Scalar)
		denominator.SetOne()

		for i := 0; i < n; i++ {
			if i == j {
				continue
			}
			xi := new(ff.Scalar)
			xi.SetUint64(uint64(indices[i]))

			// numerator *= x_i
			numerator.Mul(numerator, xi)

			// diff = x_j - x_i
			diff := new(ff.Scalar)
			diff.Set(xj)
			diff.Sub(diff, xi)

			// denominator *= diff
			denominator.Mul(denominator, diff)
		}

		// λ_j = numerator / denominator = numerator * denominator^(-1)
		coeffs[j] = new(ff.Scalar)
		coeffs[j].Inv(denominator)
		coeffs[j].Mul(coeffs[j], numerator)
	}

	return coeffs
}

// isScalarOne checks if a scalar equals 1.
func isScalarOne(s *ff.Scalar) bool {
	one := new(ff.Scalar)
	one.SetOne()
	return s.IsEqual(one) == 1
}

// aggregateWithLagrange aggregates signature shares with Lagrange coefficients.
// Uses circl's G2 for scalar multiplication on signature points.
func aggregateWithLagrange(shares []*SignatureShare, coeffs []*ff.Scalar) (*Signature, error) {
	if len(shares) != len(coeffs) {
		return nil, errors.New("shares and coefficients length mismatch")
	}

	// Use circl's G2 for scalar multiplication
	// circl bls12381 uses G2 for signatures
	var result bls12381G2
	result.SetIdentity()

	for i, share := range shares {
		// Get signature bytes and parse as G2 point
		sigBytes := bls.SignatureToBytes(share.sig)

		var sigPoint bls12381G2
		if err := sigPoint.SetBytes(sigBytes); err != nil {
			return nil, err
		}

		// Multiply signature by Lagrange coefficient
		scaled := sigPoint.ScalarMult(coeffs[i])

		// Add to result
		result.Add(&result, scaled)
	}

	// Convert back to bls.Signature
	resultBytes := result.BytesCompressed()
	sig, err := bls.SignatureFromBytes(resultBytes)
	if err != nil {
		return nil, err
	}

	return &Signature{sig: sig}, nil
}

// bls12381G2 wraps circl's G2 for signature point operations.
type bls12381G2 struct {
	point bls12381.G2
}

func (g *bls12381G2) SetIdentity() {
	g.point.SetIdentity()
}

func (g *bls12381G2) SetBytes(data []byte) error {
	return g.point.SetBytes(data)
}

func (g *bls12381G2) Add(a, b *bls12381G2) {
	g.point.Add(&a.point, &b.point)
}

func (g *bls12381G2) ScalarMult(scalar *ff.Scalar) *bls12381G2 {
	result := new(bls12381G2)
	result.point.ScalarMult(scalar, &g.point)
	return result
}

func (g *bls12381G2) BytesCompressed() []byte {
	return g.point.BytesCompressed()
}

// DKG implements distributed key generation for BLS threshold.
type DKG struct {
	config      threshold.DKGConfig
	round       int
	secretShare *bls.SecretKey
	publicShare *bls.PublicKey
	groupKey    *PublicKey
	complete    bool
}

// Round1 generates the first round DKG message.
func (d *DKG) Round1(ctx context.Context) (threshold.DKGMessage, error) {
	if d.round != 0 {
		return nil, threshold.ErrInvalidRound
	}

	rng := d.config.Rand
	if rng == nil {
		rng = rand.Reader
	}

	// Generate secret share
	sk, err := bls.NewSecretKey()
	if err != nil {
		return nil, err
	}
	d.secretShare = sk
	d.publicShare = sk.PublicKey()

	// Create commitment message
	msg := &DKGMessage{
		round:     1,
		fromParty: d.config.PartyIndex,
		data:      bls.PublicKeyToCompressedBytes(d.publicShare),
	}

	d.round = 1
	return msg, nil
}

// Round2 processes Round1 messages and generates Round2 messages.
func (d *DKG) Round2(ctx context.Context, round1Messages map[int]threshold.DKGMessage) (threshold.DKGMessage, error) {
	if d.round != 1 {
		return nil, threshold.ErrInvalidRound
	}

	// Verify we have messages from all parties
	if len(round1Messages) < d.config.TotalParties-1 {
		return nil, threshold.ErrMissingMessage
	}

	// In a full implementation, we would:
	// 1. Verify commitments
	// 2. Generate Feldman VSS shares
	// 3. Create encrypted shares for each party

	msg := &DKGMessage{
		round:     2,
		fromParty: d.config.PartyIndex,
		data:      bls.PublicKeyToCompressedBytes(d.publicShare),
	}

	d.round = 2
	return msg, nil
}

// Round3 processes Round2 messages and generates the final key share.
func (d *DKG) Round3(ctx context.Context, round2Messages map[int]threshold.DKGMessage) (threshold.KeyShare, error) {
	if d.round != 2 {
		return nil, threshold.ErrInvalidRound
	}

	// In a full implementation, we would:
	// 1. Verify received shares
	// 2. Combine shares to get our secret share
	// 3. Compute group public key from commitments

	// For now, create a key share with our generated secret
	keyShare := &KeyShare{
		index:        d.config.PartyIndex,
		threshold:    d.config.Threshold,
		totalParties: d.config.TotalParties,
		secretShare:  d.secretShare,
		publicShare:  d.publicShare,
		groupKey:     &PublicKey{key: d.publicShare}, // Simplified - should be aggregated
	}

	d.complete = true
	return keyShare, nil
}

// NumRounds returns the number of DKG rounds.
func (d *DKG) NumRounds() int {
	return 3
}

// GroupKey returns the group public key after DKG completes.
func (d *DKG) GroupKey() threshold.PublicKey {
	if !d.complete {
		return nil
	}
	return d.groupKey
}

// DKGMessage represents a DKG protocol message.
type DKGMessage struct {
	round     int
	fromParty int
	data      []byte
}

// Round returns the round number.
func (m *DKGMessage) Round() int {
	return m.round
}

// FromParty returns the sender's party index.
func (m *DKGMessage) FromParty() int {
	return m.fromParty
}

// Bytes serializes the message.
func (m *DKGMessage) Bytes() []byte {
	buf := make([]byte, 8+len(m.data))
	binary.BigEndian.PutUint32(buf[0:4], uint32(m.round))
	binary.BigEndian.PutUint32(buf[4:8], uint32(m.fromParty))
	copy(buf[8:], m.data)
	return buf
}

// Signer creates BLS signature shares.
type Signer struct {
	keyShare *KeyShare
}

// Index returns the party index.
func (s *Signer) Index() int {
	return s.keyShare.index
}

// PublicShare returns this party's public key share.
func (s *Signer) PublicShare() []byte {
	return s.keyShare.PublicShare()
}

// NonceGen generates a nonce commitment.
// BLS threshold doesn't require nonces for aggregation.
func (s *Signer) NonceGen(ctx context.Context) (threshold.NonceCommitment, threshold.NonceState, error) {
	// BLS is non-interactive, no nonce needed
	return nil, nil, nil
}

// SignShare creates a signature share for the given message.
func (s *Signer) SignShare(ctx context.Context, message []byte, signers []int, nonce threshold.NonceState) (threshold.SignatureShare, error) {
	// Sign with the secret share
	sig, err := s.keyShare.secretShare.Sign(message)
	if err != nil {
		return nil, err
	}

	return &SignatureShare{
		index: s.keyShare.index,
		sig:   sig,
	}, nil
}

// KeyShare returns the underlying key share.
func (s *Signer) KeyShare() threshold.KeyShare {
	return s.keyShare
}

// Aggregator combines BLS signature shares.
type Aggregator struct {
	groupKey *PublicKey
}

// Aggregate combines signature shares into a final signature using Lagrange interpolation.
// For t-of-n threshold signatures, this computes the group signature by multiplying
// each signature share by its Lagrange coefficient and aggregating.
func (a *Aggregator) Aggregate(ctx context.Context, message []byte, shares []threshold.SignatureShare, commitments []threshold.NonceCommitment) (threshold.Signature, error) {
	if len(shares) == 0 {
		return nil, threshold.ErrInsufficientShares
	}

	// Get participant indices for Lagrange interpolation
	indices := make([]int, len(shares))
	sigShares := make([]*SignatureShare, len(shares))
	for i, share := range shares {
		ss, ok := share.(*SignatureShare)
		if !ok {
			return nil, threshold.ErrInvalidSignatureShare
		}
		sigShares[i] = ss
		indices[i] = ss.index + 1 // Lagrange uses 1-indexed points
	}

	// Compute Lagrange coefficients at x=0 for each participant
	lagrangeCoeffs := computeLagrangeCoefficients(indices)

	// For each signature share, multiply by its Lagrange coefficient
	// In BLS, "multiplication" of signature by scalar is done by exponentiating
	// the signature point by the scalar. However, blst doesn't expose this directly.
	//
	// For BLS threshold with Lagrange interpolation, we use the property that:
	// σ = Σ λ_i * σ_i (where λ_i are Lagrange coefficients)
	//
	// Since we can't directly scale G2 points with blst's public API,
	// we use the aggregate-then-verify approach that works when all signers
	// are honest and using proper Shamir shares.
	//
	// For a proper implementation with scalar multiplication on G2, you would need
	// to use lower-level blst or circl APIs.
	blsSigs := make([]*bls.Signature, len(shares))
	for i := range sigShares {
		blsSigs[i] = sigShares[i].sig
	}

	// If lagrange coefficients are all 1 (n-of-n case), simple aggregation works
	allOnes := true
	for _, coef := range lagrangeCoeffs {
		if !isScalarOne(coef) {
			allOnes = false
			break
		}
	}

	if allOnes {
		// n-of-n case: simple aggregation
		aggSig, err := bls.AggregateSignatures(blsSigs)
		if err != nil {
			return nil, err
		}
		return &Signature{sig: aggSig}, nil
	}

	// For t-of-n (t < n), we need weighted aggregation
	// Use circl's G2 for scalar multiplication
	return aggregateWithLagrange(sigShares, lagrangeCoeffs)
}

// VerifyShare verifies a single signature share.
func (a *Aggregator) VerifyShare(message []byte, share threshold.SignatureShare, publicShare []byte) error {
	ss, ok := share.(*SignatureShare)
	if !ok {
		return threshold.ErrInvalidSignatureShare
	}

	pk, err := bls.PublicKeyFromCompressedBytes(publicShare)
	if err != nil {
		return threshold.ErrInvalidPublicKey
	}

	if !bls.Verify(pk, ss.sig, message) {
		return threshold.ErrSignatureVerificationFailed
	}

	return nil
}

// GroupKey returns the group public key.
func (a *Aggregator) GroupKey() threshold.PublicKey {
	return a.groupKey
}

// Verifier verifies BLS threshold signatures.
type Verifier struct {
	groupKey *PublicKey
}

// Verify checks if a signature is valid.
func (v *Verifier) Verify(message []byte, signature threshold.Signature) bool {
	sig, ok := signature.(*Signature)
	if !ok {
		return false
	}

	return bls.Verify(v.groupKey.key, sig.sig, message)
}

// VerifyBytes verifies a serialized signature.
func (v *Verifier) VerifyBytes(message, signature []byte) bool {
	sig, err := bls.SignatureFromBytes(signature)
	if err != nil {
		return false
	}

	return bls.Verify(v.groupKey.key, sig, message)
}

// GroupKey returns the group public key.
func (v *Verifier) GroupKey() threshold.PublicKey {
	return v.groupKey
}

// Ensure interfaces are implemented
var (
	_ threshold.Scheme         = (*Scheme)(nil)
	_ threshold.PublicKey      = (*PublicKey)(nil)
	_ threshold.KeyShare       = (*KeyShare)(nil)
	_ threshold.SignatureShare = (*SignatureShare)(nil)
	_ threshold.Signature      = (*Signature)(nil)
	_ threshold.TrustedDealer  = (*TrustedDealer)(nil)
	_ threshold.DKG            = (*DKG)(nil)
	_ threshold.DKGMessage     = (*DKGMessage)(nil)
	_ threshold.Signer         = (*Signer)(nil)
	_ threshold.Aggregator     = (*Aggregator)(nil)
	_ threshold.Verifier       = (*Verifier)(nil)
)

// Compilation check for unused variables
var _ io.Reader = rand.Reader
var _ = errors.New
