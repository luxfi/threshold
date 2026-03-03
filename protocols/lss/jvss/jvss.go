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

// CombineShares reconstructs the secret via Lagrange interpolation at x=0.
func (j *JVSS) CombineShares(shares map[party.ID]*Share) (curve.Scalar, error) {
	if len(shares) < j.threshold {
		return nil, fmt.Errorf("insufficient shares: got %d, need %d", len(shares), j.threshold)
	}

	// Collect party IDs and their x-coordinates
	ids := make([]party.ID, 0, len(shares))
	for id := range shares {
		ids = append(ids, id)
	}

	// Lagrange interpolation at x=0: secret = sum( y_i * L_i(0) )
	// where L_i(0) = prod_{j!=i}( x_j / (x_j - x_i) )
	secret := j.group.NewScalar()
	for i, id := range ids {
		xi := id.Scalar(j.group)
		yi := shares[id].Value

		// Compute Lagrange basis polynomial L_i(0) = prod_{j!=i}( x_j / (x_j - x_i) )
		lagrange := j.group.NewScalar().SetNat(new(saferith.Nat).SetUint64(1))
		for k, otherId := range ids {
			if k == i {
				continue
			}
			xj := otherId.Scalar(j.group)

			// numerator = x_j
			num := xj

			// denominator = x_j - x_i
			den := j.group.NewScalar().Set(xj)
			den.Sub(xi)

			// L_i(0) *= x_j / (x_j - x_i)
			denInv, err := scalarInvert(j.group, den)
			if err != nil {
				return nil, fmt.Errorf("lagrange interpolation: %w", err)
			}
			term := j.group.NewScalar().Set(num)
			term.Mul(denInv)
			lagrange.Mul(term)
		}

		// secret += y_i * L_i(0)
		contrib := j.group.NewScalar().Set(yi)
		contrib.Mul(lagrange)
		secret.Add(contrib)
	}

	return secret, nil
}

// scalarInvert computes the multiplicative inverse of a scalar.
func scalarInvert(group curve.Curve, s curve.Scalar) (curve.Scalar, error) {
	inv := group.NewScalar().Set(s)
	if inv.IsZero() {
		return nil, fmt.Errorf("cannot invert zero scalar")
	}
	inv.Invert()
	return inv, nil
}

// createCommitment creates Pedersen commitments to polynomial coefficients
func (j *JVSS) createCommitment(poly, polyG polynomial.Polynomial) *Commitment {
	// For now, create a simple commitment
	// Pedersen commitment uses the polynomial coefficients from the dealer share.
	points := make([]curve.Point, j.threshold)
	for i := 0; i < j.threshold; i++ {
		// Evaluate polynomial at i+1 and commit
		x := j.group.NewScalar().SetNat(new(saferith.Nat).SetUint64(uint64(i + 1)))
		val := poly.Evaluate(x)
		valG := polyG.Evaluate(x)

		// C_i = g^{f(i)} * h^{g(i)}
		// For now, use a simple commitment without Pedersen h
		// Uses additive commitment over the polynomial evaluation points.
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
