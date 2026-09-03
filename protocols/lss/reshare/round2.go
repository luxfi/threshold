package reshare

import (
	"errors"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
)

// round2 distributes reshare shares
type round2 struct {
	*round1

	// Shares we receive
	shares map[party.ID]curve.Scalar
}

// message2 contains a reshare share for a party
type message2 struct {
	// Encoded as binary: curve.Scalar is an interface, and CBOR cannot decode
	// one. See the note on broadcast1.Commitments.
	Share      []byte
	Generation uint64
}

// point decodes a commitment as it travelled.
func (r *round2) point(b []byte) (curve.Point, error) {
	p := r.Group().NewPoint()
	if err := p.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	return p, nil
}

// scalar decodes a share as it travelled.
func (r *round2) scalar(b []byte) (curve.Scalar, error) {
	s := r.Group().NewScalar()
	if err := s.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	return s, nil
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

	share, err := r.scalar(body.Share)
	if err != nil {
		return err
	}
	want, err := r.point(expectedCommitment)
	if err != nil {
		return err
	}
	if !share.ActOnBase().Equal(want) {
		return errors.New("share doesn't match commitment")
	}

	return nil
}

// StoreMessage implements round.Round
func (r *round2) StoreMessage(msg round.Message) error {
	from := msg.From
	body := msg.Content.(*message2)

	share, err := r.scalar(body.Share)
	if err != nil {
		return err
	}
	r.shares[from] = share
	return nil
}

// Finalize implements round.Round
func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Send a share of our polynomial to every other new party, and keep our
	// own directly (only if we're an old party).
	//
	// Our own share is STORED, not sent. A message addressed to ourselves is
	// refused by Message.IsFor on one path and delivered on another, and round
	// 3 sums whatever is in r.shares — so sending it made this party's
	// contribution count once or twice depending on the transport, and the
	// private share then disagreed with its own public share. Storing it here
	// and never sending it is what keygen does, and it makes r.shares mean one
	// thing: every old party's evaluation at our point, ourselves included.
	if r.inOldGroup {
		for _, id := range r.newParticipants {
			share := r.poly.Evaluate(id.Scalar(r.Group()))
			if id == r.SelfID() {
				r.shares[id] = share
				continue
			}
			b, err := share.MarshalBinary()
			if err != nil {
				return nil, err
			}
			if err := r.SendMessage(out, &message2{
				Share:      b,
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
