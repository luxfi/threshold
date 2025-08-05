// Package reshare implements the LSS dynamic resharing protocol.
package reshare

import (
	"errors"

	"github.com/cronokirby/saferith"
	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
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

// Start initiates the resharing protocol
func Start(info round.Info, pl *pool.Pool, oldConfig *Config, newParties []party.ID) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		helper, err := round.NewSession(info, sessionID, pl)
		if err != nil {
			return nil, err
		}

		// Create polynomial with current share as constant term
		poly := polynomial.NewPolynomial(helper.Group(), info.Threshold, oldConfig.SecretShare)

		// Generate shares for all parties
		shares := make(map[party.ID]curve.Scalar)
		for _, id := range info.PartyIDs {
			x := id.Scalar(helper.Group())
			shares[id] = poly.Evaluate(x)
		}

		return &round1{
			Helper:       helper,
			oldConfig:    oldConfig,
			newThreshold: info.Threshold,
			newParties:   newParties,
			poly:         poly,
			shares:       shares,
		}, nil
	}
}

// round1 initiates resharing
type round1 struct {
	*round.Helper

	oldConfig    *Config
	newThreshold int
	newParties   []party.ID

	// Re-sharing polynomial
	poly   *polynomial.Polynomial
	shares map[party.ID]curve.Scalar
}

// reshareCommitment1 contains polynomial commitments
type reshareCommitment1 struct {
	round.NormalBroadcastContent
	Commitments []curve.Point
	Generation  uint64
}

// RoundNumber implements round.Content
func (reshareCommitment1) RoundNumber() round.Number { return 1 }

// BroadcastContent implements round.BroadcastRound
func (r *round1) BroadcastContent() round.BroadcastContent {
	return &reshareCommitment1{}
}

// Number implements round.Round
func (r *round1) Number() round.Number {
	return 1
}

// StoreBroadcastMessage implements round.BroadcastRound
func (r *round1) StoreBroadcastMessage(_ round.Message) error {
	// No messages to store in round 1
	return nil
}

// VerifyMessage implements round.Round
func (r *round1) VerifyMessage(_ round.Message) error {
	// No P2P messages in round 1
	return nil
}

// StoreMessage implements round.Round
func (r *round1) StoreMessage(_ round.Message) error {
	// No P2P messages in round 1
	return nil
}

// Finalize implements round.Round
func (r *round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Broadcast commitments to polynomial coefficients
	commitments := make([]curve.Point, r.newThreshold+1)
	for i := 0; i <= r.newThreshold; i++ {
		// Similar approach as keygen
		index := r.Group().NewScalar()
		indexNat := new(saferith.Nat).SetUint64(uint64(i + 1))
		index.SetNat(indexNat)
		shareAtIndex := r.poly.Evaluate(index)
		commitments[i] = shareAtIndex.ActOnBase()
	}

	// Create commitment message
	commitment := &reshareCommitment1{
		Commitments: commitments,
		Generation:  r.oldConfig.Generation + 1,
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

// round2 distributes shares
type round2 struct {
	*round1
	commitments map[party.ID][]curve.Point
}

// reshareShare2 contains a reshared secret share
type reshareShare2 struct {
	Share      curve.Scalar
	Generation uint64
}

// RoundNumber implements round.Content
func (reshareShare2) RoundNumber() round.Number { return 2 }

// Number implements round.Round
func (r *round2) Number() round.Number {
	return 2
}

// BroadcastContent implements round.BroadcastRound
func (r *round2) BroadcastContent() round.BroadcastContent {
	return &reshareCommitment1{}
}

// StoreBroadcastMessage implements round.BroadcastRound
func (r *round2) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*reshareCommitment1)
	if !ok {
		return round.ErrInvalidContent
	}

	if len(body.Commitments) != r.newThreshold+1 {
		return errors.New("wrong number of commitments")
	}

	if body.Generation != r.oldConfig.Generation+1 {
		return errors.New("wrong generation")
	}

	// Verify sender is an old party (has resharing rights)
	isOldParty := false
	for _, id := range r.oldConfig.PartyIDs {
		if id == from {
			isOldParty = true
			break
		}
	}
	if !isOldParty {
		return errors.New("sender is not an old party")
	}

	// Verify commitments are valid points
	for _, c := range body.Commitments {
		if c == nil || c.IsIdentity() {
			return errors.New("invalid commitment")
		}
	}

	// Verify first commitment matches sender's public share
	expectedFirst := r.oldConfig.PublicShares[from]
	if !body.Commitments[0].Equal(expectedFirst) {
		return errors.New("first commitment doesn't match public share")
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
		msg := &reshareShare2{
			Share:      share,
			Generation: r.oldConfig.Generation + 1,
		}
		if err := r.SendMessage(out, msg, id); err != nil {
			return nil, err
		}
	}

	// Add own commitments if we're an old party
	for _, oldID := range r.oldConfig.PartyIDs {
		if oldID == r.SelfID() {
			myCommitments := make([]curve.Point, r.newThreshold+1)
			for i := 0; i <= r.newThreshold; i++ {
				index := r.Group().NewScalar()
				indexNat := new(saferith.Nat).SetUint64(uint64(i + 1))
				index.SetNat(indexNat)
				shareAtIndex := r.poly.Evaluate(index)
				myCommitments[i] = shareAtIndex.ActOnBase()
			}
			r.commitments[r.SelfID()] = myCommitments
			break
		}
	}

	return &round3{
		round2: r,
		shares: make(map[party.ID]curve.Scalar),
	}, nil
}

// MessageContent implements round.Round
func (r *round2) MessageContent() round.Content {
	return &reshareShare2{}
}

// round3 verifies shares and produces new config
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
	body, ok := msg.Content.(*reshareShare2)
	if !ok {
		return round.ErrInvalidContent
	}

	if body.Generation != r.oldConfig.Generation+1 {
		return errors.New("wrong generation")
	}

	// Verify share against commitments
	commitments, ok := r.commitments[from]
	if !ok {
		return errors.New("missing commitments from sender")
	}

	// Verify share is consistent with commitment
	myScalar := r.SelfID().Scalar(r.Group())

	expected := r.Group().NewPoint()
	one := new(saferith.Nat).SetUint64(1)
	xPower := r.Group().NewScalar().SetNat(one) // x^0 = 1

	for k := 0; k <= r.newThreshold; k++ {
		// commitment_k^(x^k)
		term := xPower.Act(commitments[k])
		expected = expected.Add(term)

		// Update x^k to x^(k+1)
		if k < r.newThreshold {
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
	body := msg.Content.(*reshareShare2)
	r.shares[from] = body.Share
	return nil
}

// Finalize implements round.Round
func (r *round3) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Compute final secret share
	finalShare := r.Group().NewScalar()

	// If we're an old party, add our own contribution
	isOldParty := false
	for _, id := range r.oldConfig.PartyIDs {
		if id == r.SelfID() {
			isOldParty = true
			myX := r.SelfID().Scalar(r.Group())
			finalShare = r.poly.Evaluate(myX)
			break
		}
	}

	// Add shares from other old parties
	for id, share := range r.shares {
		// Check if sender is old party
		for _, oldID := range r.oldConfig.PartyIDs {
			if oldID == id {
				finalShare = finalShare.Add(share)
				break
			}
		}
	}

	// For new parties, the share is just the sum of received shares
	if !isOldParty {
		finalShare = r.Group().NewScalar()
		for _, share := range r.shares {
			finalShare = finalShare.Add(share)
		}
	}

	// Compute public shares for all parties
	publicShares := make(map[party.ID]curve.Point)
	for _, id := range r.PartyIDs() {
		x := id.Scalar(r.Group())

		pubShare := r.Group().NewPoint()
		for from, commitments := range r.commitments {
			// Only include contributions from old parties
			for _, oldID := range r.oldConfig.PartyIDs {
				if oldID == from {
					// Evaluate polynomial at x
					contrib := r.Group().NewPoint()
					one := new(saferith.Nat).SetUint64(1)
					xPower := r.Group().NewScalar().SetNat(one) // x^0 = 1

					for k := 0; k <= r.newThreshold; k++ {
						// commitment_k^(x^k)
						term := xPower.Act(commitments[k])
						contrib = contrib.Add(term)

						// Update x^k to x^(k+1)
						if k < r.newThreshold {
							xPower = xPower.Mul(x)
						}
					}
					pubShare = pubShare.Add(contrib)
					break
				}
			}
		}
		publicShares[id] = pubShare
	}

	// Create new config with updated generation
	newConfig := &Config{
		ID:           r.SelfID(),
		Group:        r.Group(),
		Threshold:    r.newThreshold,
		Generation:   r.oldConfig.Generation + 1,
		SecretShare:  finalShare,
		PublicKey:    r.oldConfig.PublicKey, // Public key remains the same
		PublicShares: publicShares,
		PartyIDs:     r.PartyIDs(),
	}

	// Return result
	return r.ResultRound(newConfig), nil
}

// MessageContent implements round.Round
func (r *round3) MessageContent() round.Content {
	return &reshareShare2{}
}

