package jvss

import (
	"crypto/rand"
	"fmt"

	"github.com/cronokirby/saferith"
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

// Share is a party's evaluation of the dealer's polynomial.
type Share struct {
	Value curve.Scalar
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
func (j *JVSS) GenerateShares() (map[party.ID]*Share, *polynomial.Exponent, curve.Scalar, error) {
	secret := sample.Scalar(rand.Reader, j.group)
	poly := polynomial.NewPolynomial(j.group, j.threshold-1, secret)

	// The commitment is the polynomial in the exponent: F(X) = [f(X)]·G, one
	// point per COEFFICIENT. Verification is then F(x) == [f(x)]·G, which is
	// what makes the sharing verifiable and needs no separate proof.
	commitment := polynomial.NewPolynomialExponent(poly)

	shares := make(map[party.ID]*Share, len(j.parties))
	for _, id := range j.parties {
		shares[id] = &Share{Value: poly.Evaluate(id.Scalar(j.group))}
	}
	return shares, commitment, secret, nil
}

// VerifyShare verifies a share received from another party.
func (j *JVSS) VerifyShare(share *Share, commitment *polynomial.Exponent, partyID party.ID) bool {
	if share == nil || share.Value == nil || commitment == nil {
		return false
	}
	return share.Value.ActOnBase().Equal(commitment.Evaluate(partyID.Scalar(j.group)))
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
func (j *JVSS) VerifyAndCombine(allShares map[party.ID]map[party.ID]*Share, commitments map[party.ID]*polynomial.Exponent) (curve.Scalar, error) {
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
