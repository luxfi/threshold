// Package bls provides threshold BLS signature functionality
// using proper Shamir secret sharing and Lagrange interpolation.
package bls

import (
	"context"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/cloudflare/circl/ecc/bls12381/ff"
	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/party"
)

// Config holds BLS threshold signing configuration
type Config struct {
	// ID is this party's identifier
	ID party.ID

	// Threshold is the minimum number of parties needed to sign (t in t-of-n)
	Threshold int

	// TotalParties is the total number of parties
	TotalParties int

	// PublicKey is the aggregate public key
	PublicKey *bls.PublicKey

	// SecretShare is this party's secret key share
	SecretShare *bls.SecretKey

	// VerificationKeys are the public keys for each party's share
	VerificationKeys map[party.ID]*bls.PublicKey
}

// SignatureShare represents a party's contribution to a threshold signature
type SignatureShare struct {
	PartyID   party.ID
	Signature *bls.Signature
}

// Sign creates a partial BLS signature with this party's share
func (c *Config) Sign(message []byte) (*SignatureShare, error) {
	if c.SecretShare == nil {
		return nil, errors.New("no secret share available")
	}

	// Sign with our share
	sig, err := c.SecretShare.Sign(message)
	if err != nil {
		return nil, err
	}

	return &SignatureShare{
		PartyID:   c.ID,
		Signature: sig,
	}, nil
}

// AggregateSignatures combines threshold signature shares using Lagrange interpolation.
// This produces a valid signature that verifies against the group public key.
func AggregateSignatures(shares []*SignatureShare, threshold int) (*bls.Signature, error) {
	if len(shares) < threshold {
		return nil, fmt.Errorf("insufficient signatures: have %d, need %d", len(shares), threshold)
	}

	// Use exactly threshold shares
	shares = shares[:threshold]

	// Get participant IDs for Lagrange interpolation
	participants := make([]party.ID, len(shares))
	for i, share := range shares {
		participants[i] = share.PartyID
	}

	// Compute Lagrange coefficients at x=0
	blsCurve := curve.BLS12381G1()
	lagrangeCoeffs := polynomial.Lagrange(blsCurve, participants)

	// Aggregate signatures with Lagrange weighting
	// σ = Σ λ_i * σ_i (scalar multiplication on G2 points)
	var result bls12381.G2
	result.SetIdentity()

	for _, share := range shares {
		// Get Lagrange coefficient for this party
		coeff := lagrangeCoeffs[share.PartyID]
		coeffBLS := coeff.(*curve.BLS12381Scalar)

		// Get signature bytes and parse as G2 point
		sigBytes := bls.SignatureToBytes(share.Signature)
		var sigPoint bls12381.G2
		if err := sigPoint.SetBytes(sigBytes); err != nil {
			return nil, fmt.Errorf("invalid signature from party %s: %w", share.PartyID, err)
		}

		// Get scalar bytes for multiplication
		scalarBytes, _ := coeffBLS.MarshalBinary()
		scalar := new(ff.Scalar)
		scalar.SetBytes(scalarBytes)

		// Multiply signature by Lagrange coefficient
		var scaled bls12381.G2
		scaled.ScalarMult(scalar, &sigPoint)

		// Add to result
		result.Add(&result, &scaled)
	}

	// Convert back to bls.Signature
	resultBytes := result.BytesCompressed()
	sig, err := bls.SignatureFromBytes(resultBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create final signature: %w", err)
	}

	return sig, nil
}

// VerifyPartialSignature verifies a signature share from a specific party
func (c *Config) VerifyPartialSignature(share *SignatureShare, message []byte) bool {
	pubKey, ok := c.VerificationKeys[share.PartyID]
	if !ok {
		return false
	}

	return bls.Verify(pubKey, share.Signature, message)
}

// VerifyAggregateSignature verifies the final aggregated signature
func (c *Config) VerifyAggregateSignature(message []byte, sig *bls.Signature) bool {
	return bls.Verify(c.PublicKey, sig, message)
}

// TrustedDealer generates key shares using a trusted dealer.
// This uses Shamir's secret sharing to distribute the master key.
type TrustedDealer struct {
	Threshold    int
	TotalParties int
}

// GenerateShares creates key shares for all parties.
// Returns the shares and the group public key.
func (d *TrustedDealer) GenerateShares(ctx context.Context, partyIDs []party.ID) (map[party.ID]*bls.SecretKey, *bls.PublicKey, error) {
	if len(partyIDs) != d.TotalParties {
		return nil, nil, fmt.Errorf("party count mismatch: got %d, want %d", len(partyIDs), d.TotalParties)
	}

	// Generate master secret key
	masterSK, err := bls.NewSecretKey()
	if err != nil {
		return nil, nil, err
	}

	// Compute group public key
	groupPK := masterSK.PublicKey()

	// Create polynomial for Shamir sharing
	// f(x) = a_0 + a_1*x + ... + a_t*x^t where a_0 = masterSK
	blsCurve := curve.BLS12381G1()

	// Convert master secret key to scalar
	masterScalar := blsCurve.NewScalar().(*curve.BLS12381Scalar)
	masterScalar.SetBytes(bls.SecretKeyToBytes(masterSK))

	// Generate polynomial with master secret as constant term
	// For t-of-n threshold, polynomial degree is t-1 (so t points uniquely determine it)
	poly := polynomial.NewPolynomial(blsCurve, d.Threshold-1, masterScalar)

	// Generate shares by evaluating polynomial at each party's ID
	shares := make(map[party.ID]*bls.SecretKey, len(partyIDs))
	for _, id := range partyIDs {
		// Evaluate polynomial at party's scalar ID
		shareScalar := poly.Evaluate(id.Scalar(blsCurve))

		// Convert scalar to secret key
		shareBytes, _ := shareScalar.MarshalBinary()
		sk, err := bls.SecretKeyFromBytes(shareBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create share for %s: %w", id, err)
		}
		shares[id] = sk
	}

	return shares, groupPK, nil
}

// GetVerificationKeys computes public keys for each share (for verification).
func GetVerificationKeys(shares map[party.ID]*bls.SecretKey) map[party.ID]*bls.PublicKey {
	vks := make(map[party.ID]*bls.PublicKey, len(shares))
	for id, sk := range shares {
		vks[id] = sk.PublicKey()
	}
	return vks
}

// NewConfig creates a Config from generated shares.
func NewConfig(id party.ID, threshold, totalParties int, secretShare *bls.SecretKey, groupPK *bls.PublicKey, verificationKeys map[party.ID]*bls.PublicKey) *Config {
	return &Config{
		ID:               id,
		Threshold:        threshold,
		TotalParties:     totalParties,
		PublicKey:        groupPK,
		SecretShare:      secretShare,
		VerificationKeys: verificationKeys,
	}
}
