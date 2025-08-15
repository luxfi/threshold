package refresh

import (
	"errors"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/ringtail/config"
)

// Start initiates the Ringtail key refresh protocol
// This protocol refreshes shares while maintaining the same public key
func Start(cfg *config.Config, newParticipants []party.ID, newThreshold int, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		// Validate parameters
		if newThreshold < 1 || newThreshold > len(newParticipants) {
			return nil, errors.New("invalid threshold")
		}

		// Check if we're part of the new group
		inNewGroup := false
		for _, id := range newParticipants {
			if id == cfg.ID {
				inNewGroup = true
				break
			}
		}
		if !inNewGroup {
			return nil, errors.New("self not in new participant list")
		}

		info := round.Info{
			ProtocolID:       "ringtail/refresh",
			FinalRoundNumber: 3, // Refresh has 3 rounds
			SelfID:           cfg.ID,
			PartyIDs:         newParticipants,
			Threshold:        newThreshold,
		}

		helper, err := round.NewSession(info, sessionID, pl)
		if err != nil {
			return nil, err
		}

		// Start with round 1
		return &refreshRound1{
			Helper:          helper,
			config:          cfg,
			newParticipants: newParticipants,
			newThreshold:    newThreshold,
			shares:          make(map[party.ID][]byte),
		}, nil
	}
}

// refreshRound1 initiates the refresh process
type refreshRound1 struct {
	*round.Helper
	config          *config.Config
	newParticipants []party.ID
	newThreshold    int
	shares          map[party.ID][]byte

	// New polynomial for refresh
	newPolynomial []int
}

// Number implements round.Round
func (r *refreshRound1) Number() round.Number {
	return 1
}

// MessageContent implements round.Round
func (r *refreshRound1) MessageContent() round.Content {
	return nil // Round 1 is broadcast only
}

// BroadcastContent implements round.BroadcastRound
func (r *refreshRound1) BroadcastContent() round.BroadcastContent {
	return &refreshBroadcast1{}
}

// VerifyMessage implements round.Round
func (r *refreshRound1) VerifyMessage(_ round.Message) error {
	return nil
}

// StoreMessage implements round.Round
func (r *refreshRound1) StoreMessage(_ round.Message) error {
	return nil
}

// StoreBroadcastMessage implements round.BroadcastRound
func (r *refreshRound1) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*refreshBroadcast1)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// Validate commitment
	if len(body.Commitment) < 32 {
		return errors.New("invalid commitment")
	}

	return nil
}

// Finalize implements round.Round
func (r *refreshRound1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Generate new random polynomial for refresh
	params := r.config.GetParameters()
	r.newPolynomial = generateRefreshPolynomial(params.N, params.Q)

	// Create commitment to new polynomial
	commitment, decommit := createPolynomialCommitment(r.newPolynomial, *r.Hash())

	// Broadcast commitment
	if err := r.BroadcastMessage(out, &refreshBroadcast1{
		Commitment: commitment,
	}); err != nil {
		return nil, err
	}

	// Move to round 2
	return &refreshRound2{
		Helper:          r.Helper,
		config:          r.config,
		newParticipants: r.newParticipants,
		newThreshold:    r.newThreshold,
		shares:          r.shares,
		newPolynomial:   r.newPolynomial,
		decommit:        decommit,
	}, nil
}

// refreshBroadcast1 contains commitment for refresh
type refreshBroadcast1 struct {
	round.NormalBroadcastContent
	Commitment []byte
}

// RoundNumber implements round.Content
func (refreshBroadcast1) RoundNumber() round.Number {
	return 1
}
