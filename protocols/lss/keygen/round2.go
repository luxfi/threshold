package keygen

import (
	"errors"
	"sync"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/internal/types"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/party"
)

// round2 receives commitments and sends shares
type round2 struct {
	*round.Helper

	// Our polynomial from round 1
	poly *polynomial.Polynomial

	// Commitments from all parties: commitments[i][j] = g^f_i(j)
	commitments map[party.ID]map[party.ID]curve.Point

	// Chain keys from all parties
	chainKeys map[party.ID]types.RID

	// Shares we receive - using sync.Map for thread safety
	shares sync.Map // map[party.ID]curve.Scalar
}

// message2 contains the secret share for a party
type message2 struct {
	// Share encoded as binary for CBOR compatibility
	Share []byte
}

// Round2 doesn't broadcast, so we don't implement BroadcastContent
// This ensures round2 doesn't implement the BroadcastRound interface

// Number implements round.Round
func (r *round2) Number() round.Number {
	return 2
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

	// Unmarshal the share
	share := r.Group().NewScalar()
	if err := share.UnmarshalBinary(body.Share); err != nil {
		return errors.New("invalid share encoding")
	}

	// Verify share against commitment
	commitments, ok := r.commitments[from]
	if !ok {
		return errors.New("missing commitments from sender")
	}

	// Check g^share = commitment[to]
	expectedCommitment, ok := commitments[to]
	if !ok {
		return errors.New("missing commitment for our ID")
	}

	sharePoint := share.ActOnBase()
	if !sharePoint.Equal(expectedCommitment) {
		return errors.New("share doesn't match commitment")
	}

	return nil
}

// StoreMessage implements round.Round
func (r *round2) StoreMessage(msg round.Message) error {
	from := msg.From
	body := msg.Content.(*message2)

	// Unmarshal the share
	share := r.Group().NewScalar()
	if err := share.UnmarshalBinary(body.Share); err != nil {
		return errors.New("invalid share encoding")
	}

	// Store using sync.Map for thread safety
	r.shares.Store(from, share)
	return nil
}

// Finalize implements round.Round
func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Check if we've already sent shares
	_, hasSelfShare := r.shares.Load(r.SelfID())

	// First time: Send shares to each party
	if !hasSelfShare {
		for _, id := range r.OtherPartyIDs() {
			x := id.Scalar(r.Group())
			share := r.poly.Evaluate(x)

			// Marshal the share for CBOR
			shareBytes, err := share.MarshalBinary()
			if err != nil {
				return nil, errors.New("failed to marshal share")
			}

			if err := r.SendMessage(out, &message2{
				Share: shareBytes,
			}, id); err != nil {
				return nil, err
			}
		}

		// Our own share
		ownX := r.SelfID().Scalar(r.Group())
		r.shares.Store(r.SelfID(), r.poly.Evaluate(ownX))

		// Return self to wait for incoming shares
		return r, nil
	}

	// Count the number of shares we have
	shareCount := 0
	r.shares.Range(func(_, _ interface{}) bool {
		shareCount++
		return true
	})

	// Check if we have all shares before advancing
	if shareCount < r.N() {
		// Still waiting for shares
		return r, nil
	}

	// Convert sync.Map back to regular map for round3
	shares := make(map[party.ID]curve.Scalar)
	r.shares.Range(func(key, value interface{}) bool {
		id := key.(party.ID)
		shares[id] = value.(curve.Scalar)
		return true
	})

	// We have all shares, advance to round3
	return &round3{
		Helper:      r.Helper,
		commitments: r.commitments,
		chainKeys:   r.chainKeys,
		shares:      shares,
	}, nil
}

// Note: Round2 processes the broadcasts that were sent in round1.
// The broadcasts are already stored in the handler and passed to round2
// when it's created.
