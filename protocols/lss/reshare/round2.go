package reshare

import (
	"errors"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/internal/types"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
)

// round2 distributes reshare shares
type round2 struct {
	*round1
	
	// Commitments from all parties
	commitments map[party.ID]map[party.ID]curve.Point
	
	// Chain keys from all parties
	chainKeys map[party.ID]types.RID
	
	// Shares we receive
	shares map[party.ID]curve.Scalar
}

// message2 contains a reshare share for a party
type message2 struct {
	Share      curve.Scalar
	Generation uint64
}

// Number implements round.Round
func (r *round2) Number() round.Number {
	return 2
}

// BroadcastContent implements round.BroadcastRound
func (r *round2) BroadcastContent() round.BroadcastContent {
	return nil // No broadcast in round 2
}

// MessageContent implements round.Round
func (r *round2) MessageContent() round.Content {
	return &message2{}
}

// RoundNumber implements round.Content
func (message2) RoundNumber() round.Number {
	return 2
}

// VerifyMessage implements round.Round
func (r *round2) VerifyMessage(msg round.Message) error {
	from, to := msg.From, msg.To
	body, ok := msg.Content.(*message2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	
	if to != r.SelfID() {
		return errors.New("message not for us")
	}
	
	if body.Generation != r.oldConfig.Generation+1 {
		return errors.New("wrong generation")
	}
	
	// Verify share against commitment
	commitments, ok := r.commitments[from]
	if !ok {
		return errors.New("missing commitments from sender")
	}
	
	// Check g^share = commitment[to]
	expectedCommitment, ok := commitments[to]
	if !ok {
		// If sender is not an old party, they shouldn't send shares
		isOldParty := false
		for _, id := range r.oldConfig.PartyIDs() {
			if id == from {
				isOldParty = true
				break
			}
		}
		if !isOldParty {
			return errors.New("new party shouldn't send shares")
		}
		return errors.New("missing commitment for our ID")
	}
	
	sharePoint := body.Share.ActOnBase()
	if !sharePoint.Equal(expectedCommitment) {
		return errors.New("share doesn't match commitment")
	}
	
	return nil
}

// StoreMessage implements round.Round
func (r *round2) StoreMessage(msg round.Message) error {
	from := msg.From
	body := msg.Content.(*message2)
	
	r.shares[from] = body.Share
	return nil
}

// Finalize implements round.Round
func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Send shares to new parties (only if we're an old party)
	if r.inOldGroup {
		for _, id := range r.newParticipants {
			x := id.Scalar(r.Group())
			share := r.poly.Evaluate(x)
			
			if err := r.SendMessage(out, &message2{
				Share:      share,
				Generation: r.oldConfig.Generation + 1,
			}, id); err != nil {
				return nil, err
			}
		}
	}
	
	return &round3{
		round2: r,
	}, nil
}

// StoreBroadcastMessage implements round.BroadcastRound
func (r *round2) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast1)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	
	// Verify generation
	if body.Generation != r.oldConfig.Generation+1 {
		return errors.New("wrong generation in broadcast")
	}
	
	// Store commitments and chain keys
	r.commitments[from] = body.Commitments
	r.chainKeys[from] = body.ChainKey
	
	return nil
}