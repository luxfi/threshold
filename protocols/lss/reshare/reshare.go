// Package reshare implements the LSS dynamic resharing protocol.
package reshare

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

// round1 initiates resharing
type round1 struct {
	*round.Helper
	
	oldConfig    *lss.Config
	newThreshold int
	newParties   []party.ID
	
	// Re-sharing polynomial
	poly   polynomial.Polynomial
	shares map[party.ID]curve.Scalar
}

// Start initiates the resharing protocol
func Start(info round.Info, pl *pool.Pool, oldConfig *lss.Config, newParties []party.ID) (round.Session, error) {
	helper, err := round.NewSession(info, oldConfig.ID, info.PartyIDs, nil)
	if err != nil {
		return nil, err
	}
	
	// Create polynomial with current share as constant term
	poly := polynomial.NewPolynomial(info.Group, info.Threshold, oldConfig.SecretShare)
	
	// Generate shares for all parties (old and new)
	shares := make(map[party.ID]curve.Scalar)
	for i, id := range info.PartyIDs {
		x := info.Group.NewScalar().SetNat(uint(i + 1))
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
	commitments := make([]curve.Point, r.newThreshold)
	for i := 0; i < r.newThreshold; i++ {
		coeff := r.poly.Coefficient(i)
		commitments[i] = coeff.ActOnBase()
	}
	
	// Create commitment message
	commitment := &reshareCommitment{
		commitments: commitments,
		generation:  r.oldConfig.Generation + 1,
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
	return &reshareCommitment{}
}

// Number implements round.Round
func (r *round1) Number() round.Number {
	return 1
}

// reshareCommitment contains polynomial commitments
type reshareCommitment struct {
	round.NormalBroadcastContent
	commitments []curve.Point
	generation  uint64
}

// round2 distributes shares
type round2 struct {
	*round1
	commitments map[party.ID][]curve.Point
}

// VerifyMessage implements round.Round
func (r *round2) VerifyMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*reshareCommitment)
	if !ok {
		return round.ErrInvalidContent
	}
	
	if len(body.commitments) != r.newThreshold {
		return errors.New("wrong number of commitments")
	}
	
	if body.generation != r.oldConfig.Generation+1 {
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
	for _, c := range body.commitments {
		if c == nil || c.IsIdentity() {
			return errors.New("invalid commitment")
		}
	}
	
	// Verify first commitment matches sender's public share
	expectedFirst := r.oldConfig.PublicShares[from]
	if !body.commitments[0].Equal(expectedFirst) {
		return errors.New("first commitment doesn't match public share")
	}
	
	return nil
}

// StoreMessage implements round.Round
func (r *round2) StoreMessage(msg round.Message) error {
	from := msg.From
	body := msg.Content.(*reshareCommitment)
	r.commitments[from] = body.commitments
	return nil
}

// Finalize implements round.Round
func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Send shares to each party
	for _, id := range r.OtherPartyIDs() {
		share := r.shares[id]
		msg := &reshareShare{
			share:      share,
			generation: r.oldConfig.Generation + 1,
		}
		if err := r.SendMessage(out, msg, id); err != nil {
			return nil, err
		}
	}
	
	// Add own commitments if we're an old party
	for _, oldID := range r.oldConfig.PartyIDs {
		if oldID == r.SelfID() {
			myCommitments := make([]curve.Point, r.newThreshold)
			for i := 0; i < r.newThreshold; i++ {
				coeff := r.poly.Coefficient(i)
				myCommitments[i] = coeff.ActOnBase()
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
	return &reshareShare{}
}

// Number implements round.Round
func (r *round2) Number() round.Number {
	return 2
}

// reshareShare contains a reshared secret share
type reshareShare struct {
	round.NormalBroadcastContent
	share      curve.Scalar
	generation uint64
}

// round3 verifies shares and produces new config
type round3 struct {
	*round2
	shares map[party.ID]curve.Scalar
}

// VerifyMessage implements round.Round
func (r *round3) VerifyMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*reshareShare)
	if !ok {
		return round.ErrInvalidContent
	}
	
	if body.generation != r.oldConfig.Generation+1 {
		return errors.New("wrong generation")
	}
	
	// Verify share against commitments
	commitments, ok := r.commitments[from]
	if !ok {
		return errors.New("missing commitments from sender")
	}
	
	// Verify share is consistent with commitment
	myIndex := r.PartyIDIndex(r.SelfID()) + 1
	x := r.Group().NewScalar().SetNat(uint(myIndex))
	
	expected := r.Group().NewPoint()
	for k := 0; k < r.newThreshold; k++ {
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
	body := msg.Content.(*reshareShare)
	r.shares[from] = body.share
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
			finalShare = r.shares[r.SelfID()]
			break
		}
	}
	
	// Add shares from other old parties
	for id, share := range r.shares {
		if id != r.SelfID() {
			// Check if sender is old party
			for _, oldID := range r.oldConfig.PartyIDs {
				if oldID == id {
					finalShare = finalShare.Add(share)
					break
				}
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
		idx := r.PartyIDIndex(id) + 1
		x := r.Group().NewScalar().SetNat(uint(idx))
		
		pubShare := r.Group().NewPoint()
		for from, commitments := range r.commitments {
			// Only include contributions from old parties
			for _, oldID := range r.oldConfig.PartyIDs {
				if oldID == from {
					// Compute contribution from this party's polynomial
					contrib := r.Group().NewPoint()
					for k := 0; k < r.newThreshold; k++ {
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
					break
				}
			}
		}
		publicShares[id] = pubShare
	}
	
	// Create new config with updated generation
	newConfig := &lss.Config{
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
	r.UpdateResult(protocol.Result(newConfig))
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