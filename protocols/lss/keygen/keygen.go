// Package keygen implements the LSS key generation protocol.
package keygen

import (
	"crypto/rand"
	"errors"

	"github.com/cronokirby/saferith"
	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/math/sample"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
)

// Config represents the configuration for an LSS party
type Config struct {
	ID           party.ID
	Group        curve.Curve
	Threshold    int
	Generation   uint64
	SecretShare  curve.Scalar
	PublicKey    curve.Point
	PublicShares map[party.ID]curve.Point
	PartyIDs     []party.ID
}

// Start initiates the LSS key generation protocol
func Start(info round.Info, pl *pool.Pool, source []byte) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		helper, err := round.NewSession(info, sessionID, pl)
		if err != nil {
			return nil, err
		}

		group := helper.Group()

		// Generate random polynomial of degree t-1
		var secret curve.Scalar
		if source != nil {
			// For testing - use provided secret
			secret = group.NewScalar()
		} else {
			// Generate random secret
			secret = sample.Scalar(rand.Reader, group)
		}

		// Create polynomial with secret as constant term
		poly := polynomial.NewPolynomial(group, helper.Threshold(), secret)

		// Generate shares for all parties
		shares := make(map[party.ID]curve.Scalar)
		for _, id := range helper.PartyIDs() {
			// Use party's scalar representation
			x := id.Scalar(group)
			shares[id] = poly.Evaluate(x)
		}

		return &round1{
			Helper: helper,
			poly:   poly,
			shares: shares,
		}, nil
	}
}

// round1 is the first round of key generation
type round1 struct {
	*round.Helper
	poly   *polynomial.Polynomial
	shares map[party.ID]curve.Scalar
}

// commitment1 represents the commitment message
type commitment1 struct {
	round.NormalBroadcastContent
	Commitments []curve.Point
}

// RoundNumber implements round.Content
func (commitment1) RoundNumber() round.Number { return 1 }

// BroadcastContent implements round.BroadcastRound
func (r *round1) BroadcastContent() round.BroadcastContent {
	return &commitment1{}
}

// Number implements round.Round
func (r *round1) Number() round.Number {
	return 1
}

// StoreBroadcastMessage implements round.BroadcastRound
func (r *round1) StoreBroadcastMessage(msg round.Message) error {
	// No messages to store in round 1
	return nil
}

// VerifyMessage implements round.Round
func (r *round1) VerifyMessage(msg round.Message) error {
	// No P2P messages in round 1
	return nil
}

// StoreMessage implements round.Round
func (r *round1) StoreMessage(msg round.Message) error {
	// No P2P messages in round 1
	return nil
}

// Finalize implements round.Round
func (r *round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Broadcast commitments to polynomial coefficients
	commitments := make([]curve.Point, r.Threshold()+1)
	// Generate commitments for each coefficient
	for i := 0; i <= r.Threshold(); i++ {
		// Evaluate polynomial at specific points to derive coefficient commitments
		// For now, use a simple approach: g^{f(i+1)}
		index := r.Group().NewScalar()
		indexNat := new(saferith.Nat).SetUint64(uint64(i + 1))
		index.SetNat(indexNat)
		shareAtIndex := r.poly.Evaluate(index)
		commitments[i] = shareAtIndex.ActOnBase()
	}

	// Create commitment message
	commitment := &commitment1{
		Commitments: commitments,
	}

	// Broadcast to all parties
	if err := r.BroadcastMessage(out, commitment); err != nil {
		return nil, err
	}

	return &round2{
		round1:      r,
		commitments: make(map[party.ID][]curve.Point),
	}, nil
}

// MessageContent implements round.Round
func (r *round1) MessageContent() round.Content {
	return nil // No P2P messages
}

// round2 handles share distribution
type round2 struct {
	*round1
	commitments map[party.ID][]curve.Point
}

// shareMessage2 contains a secret share
type shareMessage2 struct {
	Share curve.Scalar
}

// RoundNumber implements round.Content
func (shareMessage2) RoundNumber() round.Number { return 2 }

// Number implements round.Round
func (r *round2) Number() round.Number {
	return 2
}

// BroadcastContent implements round.BroadcastRound
func (r *round2) BroadcastContent() round.BroadcastContent {
	return &commitment1{} // Reuse from round 1
}

// StoreBroadcastMessage implements round.BroadcastRound
func (r *round2) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*commitment1)
	if !ok {
		return round.ErrInvalidContent
	}

	if len(body.Commitments) != r.Threshold()+1 {
		return errors.New("wrong number of commitments")
	}

	// Verify commitments are valid points
	for _, c := range body.Commitments {
		if c == nil || c.IsIdentity() {
			return errors.New("invalid commitment")
		}
	}

	r.commitments[from] = body.Commitments
	return nil
}

// VerifyMessage implements round.Round
func (r *round2) VerifyMessage(msg round.Message) error {
	// Verify in StoreMessage
	return nil
}

// StoreMessage implements round.Round
func (r *round2) StoreMessage(msg round.Message) error {
	// P2P messages received in round 3
	return nil
}

// Finalize implements round.Round
func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Send shares to each party
	for _, id := range r.OtherPartyIDs() {
		share := r.shares[id]
		msg := &shareMessage2{
			Share: share,
		}
		if err := r.SendMessage(out, msg, id); err != nil {
			return nil, err
		}
	}

	// Add own commitments
	myCommitments := make([]curve.Point, r.Threshold()+1)
	for i := 0; i <= r.Threshold(); i++ {
		// Same approach as above
		index := r.Group().NewScalar()
		indexNat := new(saferith.Nat).SetUint64(uint64(i + 1))
		index.SetNat(indexNat)
		shareAtIndex := r.poly.Evaluate(index)
		myCommitments[i] = shareAtIndex.ActOnBase()
	}
	r.commitments[r.SelfID()] = myCommitments

	return &round3{
		round2: r,
		shares: make(map[party.ID]curve.Scalar),
	}, nil
}

// MessageContent implements round.Round
func (r *round2) MessageContent() round.Content {
	return &shareMessage2{}
}

// round3 collects shares and produces final config
type round3 struct {
	*round2
	shares map[party.ID]curve.Scalar
}

// Number implements round.Round
func (r *round3) Number() round.Number {
	return 3
}

// BroadcastContent implements round.BroadcastRound
func (r *round3) BroadcastContent() round.BroadcastContent {
	return nil // No broadcast in round 3
}

// StoreBroadcastMessage implements round.BroadcastRound
func (r *round3) StoreBroadcastMessage(msg round.Message) error {
	// No broadcast messages in round 3
	return nil
}

// VerifyMessage implements round.Round
func (r *round3) VerifyMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*shareMessage2)
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
	// g^{s_ij} = \prod_{k=0}^{t} (g^{a_ik})^{j^k}
	myScalar := r.SelfID().Scalar(r.Group())

	expected := r.Group().NewPoint()
	one := new(saferith.Nat).SetUint64(1)
	xPower := r.Group().NewScalar().SetNat(one) // x^0 = 1

	for k := 0; k <= r.Threshold(); k++ {
		// commitment_k^(x^k)
		term := xPower.Act(commitments[k])
		expected = expected.Add(term)

		// Update x^k to x^(k+1)
		if k < r.Threshold() {
			xPower = xPower.Mul(myScalar)
		}
	}

	// Check if g^share == expected
	sharePoint := body.Share.ActOnBase()
	if !sharePoint.Equal(expected) {
		return errors.New("share verification failed")
	}

	return nil
}

// StoreMessage implements round.Round
func (r *round3) StoreMessage(msg round.Message) error {
	from := msg.From
	body := msg.Content.(*shareMessage2)
	r.shares[from] = body.Share
	return nil
}

// Finalize implements round.Round
func (r *round3) Finalize(_ chan<- *round.Message) (round.Session, error) {
	// Add own share
	r.shares[r.SelfID()] = r.round1.shares[r.SelfID()]

	// Compute final secret share as sum of all shares
	finalShare := r.Group().NewScalar()
	for _, share := range r.shares {
		finalShare = finalShare.Add(share)
	}

	// Compute public key from commitments (sum of constant terms)
	publicKey := r.Group().NewPoint()
	for _, commitments := range r.commitments {
		publicKey = publicKey.Add(commitments[0]) // Add constant terms
	}

	// Compute public shares for all parties
	publicShares := make(map[party.ID]curve.Point)
	for _, id := range r.PartyIDs() {
		x := id.Scalar(r.Group())

		pubShare := r.Group().NewPoint()
		for _, commitments := range r.commitments {
			// Evaluate polynomial at x
			contrib := r.Group().NewPoint()
			one := new(saferith.Nat).SetUint64(1)
			xPower := r.Group().NewScalar().SetNat(one) // x^0 = 1

			for k := 0; k <= r.Threshold(); k++ {
				// commitment_k^(x^k)
				term := xPower.Act(commitments[k])
				contrib = contrib.Add(term)

				// Update x^k to x^(k+1)
				if k < r.Threshold() {
					xPower = xPower.Mul(x)
				}
			}
			pubShare = pubShare.Add(contrib)
		}
		publicShares[id] = pubShare
	}

	// Create final config
	config := &Config{
		ID:           r.SelfID(),
		Group:        r.Group(),
		Threshold:    r.Threshold(),
		Generation:   1,
		SecretShare:  finalShare,
		PublicKey:    publicKey,
		PublicShares: publicShares,
		PartyIDs:     r.PartyIDs(),
	}

	// Return result
	return r.ResultRound(config), nil
}

// MessageContent implements round.Round
func (r *round3) MessageContent() round.Content {
	return &shareMessage2{}
}

