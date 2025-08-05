// Package keygen implements the LSS key generation protocol.
package keygen

import (
	"errors"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/math/sample"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/lss"
)

// round1 is the first round of key generation
type round1 struct {
	*round.Helper

	threshold int
	secret    curve.Scalar
	poly      polynomial.Polynomial
	shares    map[party.ID]curve.Scalar
}

// Start initiates the LSS key generation protocol
func Start(info round.Info, pl *pool.Pool, source []byte) (round.Session, error) {
	if info.Threshold < 1 || info.Threshold > info.N() {
		return nil, errors.New("invalid threshold")
	}

	helper, err := round.NewSession(info, info.SelfID, info.PartyIDs, nil)
	if err != nil {
		return nil, err
	}

	// Generate random polynomial of degree t-1
	secret := info.Group.NewScalar()
	if source != nil {
		// For testing - use provided secret
		secret = info.Group.NewScalar().SetBytes(source)
	} else {
		// Generate random secret
		secret = sample.Scalar(pl, info.Group)
	}

	// Create polynomial with secret as constant term
	poly := polynomial.NewPolynomial(info.Group, info.Threshold, secret)

	// Generate shares for all parties
	shares := make(map[party.ID]curve.Scalar)
	for i, id := range info.PartyIDs {
		x := info.Group.NewScalar().SetNat(uint(i + 1))
		shares[id] = poly.Evaluate(x)
	}

	return &round1{
		Helper:    helper,
		threshold: info.Threshold,
		secret:    secret,
		poly:      poly,
		shares:    shares,
	}, nil
}

// VerifyMessage implements round.Round
func (r *round1) VerifyMessage(msg round.Message) error {
	// No messages in round 1
	return nil
}

// StoreMessage implements round.Round
func (r *round1) StoreMessage(msg round.Message) error {
	// No messages in round 1
	return nil
}

// Finalize implements round.Round
func (r *round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Broadcast commitments to polynomial coefficients
	commitments := make([]curve.Point, r.threshold)
	for i := 0; i < r.threshold; i++ {
		coeff := r.poly.Coefficient(i)
		commitments[i] = coeff.ActOnBase()
	}

	// Create commitment message
	commitment := &commitment{
		commitments: commitments,
	}

	// Broadcast to all parties
	if err := r.BroadcastMessage(out, commitment); err != nil {
		return nil, err
	}

	return &round2{
		round1: r,
		commitments: make(map[party.ID][]curve.Point),
	}, nil
}

// MessageContent implements round.Round
func (r *round1) MessageContent() round.Content {
	return &commitment{}
}

// Number implements round.Round
func (r *round1) Number() round.Number {
	return 1
}

// commitment represents the commitment message
type commitment struct {
	round.NormalBroadcastContent
	commitments []curve.Point
}

// round2 handles share distribution
type round2 struct {
	*round1
	commitments map[party.ID][]curve.Point
}

// VerifyMessage implements round.Round
func (r *round2) VerifyMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*commitment)
	if !ok {
		return round.ErrInvalidContent
	}

	if len(body.commitments) != r.threshold {
		return errors.New("wrong number of commitments")
	}

	// Verify commitments are valid points
	for _, c := range body.commitments {
		if c == nil || c.IsIdentity() {
			return errors.New("invalid commitment")
		}
	}

	return nil
}

// StoreMessage implements round.Round
func (r *round2) StoreMessage(msg round.Message) error {
	from := msg.From
	body := msg.Content.(*commitment)
	r.commitments[from] = body.commitments
	return nil
}

// Finalize implements round.Round
func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Send shares to each party
	for _, id := range r.OtherPartyIDs() {
		share := r.shares[id]
		msg := &shareMessage{
			share: share,
		}
		if err := r.SendMessage(out, msg, id); err != nil {
			return nil, err
		}
	}

	// Add own commitments
	myCommitments := make([]curve.Point, r.threshold)
	for i := 0; i < r.threshold; i++ {
		coeff := r.poly.Coefficient(i)
		myCommitments[i] = coeff.ActOnBase()
	}
	r.commitments[r.SelfID()] = myCommitments

	return &round3{
		round2: r,
		shares: make(map[party.ID]curve.Scalar),
	}, nil
}

// MessageContent implements round.Round
func (r *round2) MessageContent() round.Content {
	return &shareMessage{}
}

// Number implements round.Round
func (r *round2) Number() round.Number {
	return 2
}

// shareMessage contains a secret share
type shareMessage struct {
	round.NormalBroadcastContent
	share curve.Scalar
}

// round3 collects shares and produces final config
type round3 struct {
	*round2
	shares map[party.ID]curve.Scalar
}

// VerifyMessage implements round.Round
func (r *round3) VerifyMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*shareMessage)
	if !ok {
		return round.ErrInvalidContent
	}

	// Verify share against commitments
	commitments, ok := r.commitments[from]
	if !ok {
		return errors.New("missing commitments from sender")
	}

	// Verify share is consistent with commitment
	// For party j receiving share from party i:
	// g^{s_ij} = \prod_{k=0}^{t-1} (g^{a_ik})^{j^k}
	myIndex := r.PartyIDIndex(r.SelfID()) + 1
	x := r.Group().NewScalar().SetNat(uint(myIndex))
	
	expected := r.Group().NewPoint()
	for k := 0; k < r.threshold; k++ {
		// x^k
		exp := r.Group().NewScalar()
		if k == 0 {
			exp = r.Group().NewScalar().SetNat(1)
		} else {
			exp = x
			for j := 1; j < k; j++ {
				exp = r.Group().NewScalar().Mul(exp, x)
			}
		}
		
		// commitment^(x^k)
		term := exp.Act(commitments[k])
		expected = expected.Add(term)
	}

	// Check if g^share == expected
	sharePoint := body.share.ActOnBase()
	if !sharePoint.Equal(expected) {
		return errors.New("share verification failed")
	}

	return nil
}

// StoreMessage implements round.Round
func (r *round3) StoreMessage(msg round.Message) error {
	from := msg.From
	body := msg.Content.(*shareMessage)
	r.shares[from] = body.share
	return nil
}

// Finalize implements round.Round
func (r *round3) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Compute final secret share as sum of all shares
	finalShare := r.shares[r.SelfID()]
	for id, share := range r.shares {
		if id != r.SelfID() {
			finalShare = finalShare.Add(share)
		}
	}

	// Compute public key from commitments
	publicKey := r.Group().NewPoint()
	for _, commitments := range r.commitments {
		publicKey = publicKey.Add(commitments[0]) // Add constant terms
	}

	// Compute public shares for all parties
	publicShares := make(map[party.ID]curve.Point)
	for _, id := range r.PartyIDs() {
		idx := r.PartyIDIndex(id) + 1
		x := r.Group().NewScalar().SetNat(uint(idx))
		
		pubShare := r.Group().NewPoint()
		for from, commitments := range r.commitments {
			// Compute contribution from this party's polynomial
			contrib := r.Group().NewPoint()
			for k := 0; k < r.threshold; k++ {
				// x^k
				exp := r.Group().NewScalar()
				if k == 0 {
					exp = r.Group().NewScalar().SetNat(1)
				} else {
					exp = x
					for j := 1; j < k; j++ {
						exp = r.Group().NewScalar().Mul(exp, x)
					}
				}
				
				// commitment^(x^k)
				term := exp.Act(commitments[k])
				contrib = contrib.Add(term)
			}
			pubShare = pubShare.Add(contrib)
		}
		publicShares[id] = pubShare
	}

	// Create final config
	config := &lss.Config{
		ID:           r.SelfID(),
		Group:        r.Group(),
		Threshold:    r.threshold,
		Generation:   1,
		SecretShare:  finalShare,
		PublicKey:    publicKey,
		PublicShares: publicShares,
		PartyIDs:     r.PartyIDs(),
	}

	// Return result through Helper
	r.UpdateResult(protocol.Result(config))
	return r.ResultRound(out), nil
}

// MessageContent implements round.Round
func (r *round3) MessageContent() round.Content {
	return nil
}

// Number implements round.Round
func (r *round3) Number() round.Number {
	return 3
}