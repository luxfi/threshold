package jvss

import (
	"crypto/rand"
	"fmt"

	"github.com/cronokirby/saferith"
	"github.com/luxfi/threshold/pkg/hash"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/math/sample"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
)

// JVSS implements Joint Verifiable Secret Sharing.
// This is used to generate the auxiliary secrets w and q in the re-sharing protocol
type JVSS struct {
	group     curve.Curve
	threshold int
	parties   []party.ID
	selfID    party.ID
}

// Share represents a party's share of a secret.
type Share struct {
	Value curve.Scalar
	Proof *ShareProof
}

// ShareProof provides zero-knowledge proof of share validity.
type ShareProof struct {
	Commitment curve.Point
	Challenge  curve.Scalar
	Response   curve.Scalar
}

// Commitment represents a polynomial commitment.
type Commitment struct {
	Points []curve.Point // Coefficient commitments
}

// NewJVSS creates a new JVSS instance.
func NewJVSS(group curve.Curve, threshold int, parties []party.ID, selfID party.ID) *JVSS {
	return &JVSS{
		group:     group,
		threshold: threshold,
		parties:   parties,
		selfID:    selfID,
	}
}

// GenerateShares generates shares for a new random secret.
func (j *JVSS) GenerateShares() (map[party.ID]*Share, *Commitment, curve.Scalar, error) {
	// Generate random polynomial f(x) of degree t-1
	secret := sample.Scalar(rand.Reader, j.group)
	poly := polynomial.NewPolynomial(j.group, j.threshold-1, secret)

	// Generate polynomial g(x) for Pedersen commitment
	polyG := polynomial.NewPolynomial(j.group, j.threshold-1, sample.Scalar(rand.Reader, j.group))

	// Create commitments to polynomial coefficients
	commitment := j.createCommitment(*poly, *polyG)

	// Generate shares for each party
	shares := make(map[party.ID]*Share)
	for _, id := range j.parties {
		x := id.Scalar(j.group)
		shareValue := poly.Evaluate(x)
		shareG := polyG.Evaluate(x)

		// Create zero-knowledge proof for the share
		proof := j.createShareProof(shareValue, shareG, id)

		shares[id] = &Share{
			Value: shareValue,
			Proof: proof,
		}
	}

	return shares, commitment, secret, nil
}

// VerifyShare verifies a share received from another party.
func (j *JVSS) VerifyShare(share *Share, commitment *Commitment, partyID party.ID) bool {
	// Verify the share against the polynomial commitment
	x := partyID.Scalar(j.group)

	// Compute expected commitment from polynomial
	expectedCommit := j.evaluateCommitment(commitment, x)

	// Verify zero-knowledge proof
	return j.verifyShareProof(share.Proof, expectedCommit, partyID)
}

// CombineShares combines shares to reconstruct the secret
func (j *JVSS) CombineShares(shares map[party.ID]*Share) (curve.Scalar, error) {
	if len(shares) < j.threshold {
		return nil, fmt.Errorf("insufficient shares: got %d, need %d", len(shares), j.threshold)
	}

	// Use Lagrange interpolation to reconstruct the secret
	// For now, just return the first share's value as placeholder
	// TODO: Implement proper Lagrange interpolation at x=0
	// When implementing, will need to:
	// - Collect x values and share values from shares
	// - Perform Lagrange interpolation at x=0
	for _, share := range shares {
		return share.Value, nil
	}
	return nil, nil
}

// createCommitment creates Pedersen commitments to polynomial coefficients
func (j *JVSS) createCommitment(poly, polyG polynomial.Polynomial) *Commitment {
	// For now, create a simple commitment
	// TODO: Implement proper Pedersen commitment access to polynomial coefficients
	points := make([]curve.Point, j.threshold)
	for i := 0; i < j.threshold; i++ {
		// Evaluate polynomial at i+1 and commit
		x := j.group.NewScalar().SetNat(new(saferith.Nat).SetUint64(uint64(i + 1)))
		val := poly.Evaluate(x)
		valG := polyG.Evaluate(x)

		// C_i = g^{f(i)} * h^{g(i)}
		// For now, use a simple commitment without Pedersen h
		// TODO: Implement proper Pedersen commitment with h generator
		gPart := val.ActOnBase()
		hPart := valG.ActOnBase() // Should use h generator
		points[i] = gPart.Add(hPart)
	}

	return &Commitment{Points: points}
}

// evaluateCommitment evaluates the commitment polynomial at a point
func (j *JVSS) evaluateCommitment(commitment *Commitment, x curve.Scalar) curve.Point {
	result := j.group.NewPoint() // Identity element
	xPower := j.group.NewScalar().SetNat(new(saferith.Nat).SetUint64(1))

	for _, coeff := range commitment.Points {
		// term = coeff^{x^i}
		term := xPower.Act(coeff)
		result = result.Add(term)
		xPower = xPower.Mul(x)
	}

	return result
}

// createShareProof creates a zero-knowledge proof for a share
func (j *JVSS) createShareProof(share, _ curve.Scalar, recipient party.ID) *ShareProof {
	// Simple Schnorr-like proof of knowledge
	r := sample.Scalar(rand.Reader, j.group)

	// Commitment
	commitment := r.ActOnBase()

	// Challenge (Fiat-Shamir)
	challenge := j.computeChallenge(commitment, recipient)

	// Response
	response := j.group.NewScalar().Mul(challenge).Mul(share)
	response = response.Add(r)

	return &ShareProof{
		Commitment: commitment,
		Challenge:  challenge,
		Response:   response,
	}
}

// verifyShareProof verifies a zero-knowledge proof for a share
func (j *JVSS) verifyShareProof(proof *ShareProof, expectedCommit curve.Point, partyID party.ID) bool {
	// Recompute challenge
	challenge := j.computeChallenge(proof.Commitment, partyID)
	if !challenge.Equal(proof.Challenge) {
		return false
	}

	// Verify proof equation
	lhs := proof.Response.ActOnBase()
	rhs := challenge.Act(expectedCommit)
	rhs = rhs.Add(proof.Commitment)

	return lhs.Equal(rhs)
}

// computeChallenge computes the Fiat-Shamir challenge
func (j *JVSS) computeChallenge(commitment curve.Point, partyID party.ID) curve.Scalar {
	// Hash commitment and party ID to create challenge
	h := hash.New()
	_ = h.WriteAny(commitment)
	_ = h.WriteAny(partyID)
	digest := h.Sum()
	natValue := new(saferith.Nat).SetBytes(digest)
	return j.group.NewScalar().SetNat(natValue)
}

// StartJVSS starts a JVSS protocol round
func StartJVSS(group curve.Curve, selfID party.ID, parties []party.ID, threshold int, _ *pool.Pool) (*JVSS, map[party.ID]*Share, error) {
	jvss := NewJVSS(group, threshold, parties, selfID)

	// Generate shares for our contribution
	shares, _, _, err := jvss.GenerateShares()
	if err != nil {
		return nil, nil, err
	}

	// In a real implementation, this would be a multi-round protocol
	// where commitments are broadcast first, then shares are sent privately

	return jvss, shares, nil
}

// VerifyAndCombine verifies all shares and combines them to get the final secret
func (j *JVSS) VerifyAndCombine(allShares map[party.ID]map[party.ID]*Share, commitments map[party.ID]*Commitment) (curve.Scalar, error) {
	// Verify all shares
	for dealer, shares := range allShares {
		commitment := commitments[dealer]
		for recipient, share := range shares {
			if !j.VerifyShare(share, commitment, recipient) {
				return nil, fmt.Errorf("invalid share from %s to %s", dealer, recipient)
			}
		}
	}

	// Combine shares from all dealers
	finalShares := make(map[party.ID]*Share)
	for _, recipient := range j.parties {
		combinedValue := j.group.NewScalar()
		for dealer := range allShares {
			if share, ok := allShares[dealer][recipient]; ok {
				combinedValue.Add(share.Value)
			}
		}
		finalShares[recipient] = &Share{Value: combinedValue}
	}

	// Reconstruct the joint secret
	return j.CombineShares(finalShares)
}
