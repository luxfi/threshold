package sign

import (
	"crypto/rand"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/sample"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/lss/config"
)

// round1 generates nonces for signing
type round1 struct {
	*round.Helper

	config      *config.Config
	signers     []party.ID
	messageHash []byte

	// Our nonce pair
	k curve.Scalar // Secret nonce
	K curve.Point  // Public nonce commitment g^k
}

// broadcast1 contains the nonce commitment
type broadcast1 struct {
	round.NormalBroadcastContent

	// Public nonce commitment
	K curve.Point
}

// Number implements round.Round
func (r *round1) Number() round.Number {
	return 1
}

// BroadcastContent implements round.BroadcastRound
func (r *round1) BroadcastContent() round.BroadcastContent {
	return &broadcast1{}
}

// MessageContent implements round.Round
func (r *round1) MessageContent() round.Content {
	return nil // No P2P messages in round 1
}

// RoundNumber implements round.Content
func (broadcast1) RoundNumber() round.Number {
	return 1
}

// VerifyMessage implements round.Round
func (r *round1) VerifyMessage(_ round.Message) error {
	return nil // No P2P messages
}

// StoreMessage implements round.Round
func (r *round1) StoreMessage(_ round.Message) error {
	return nil // No P2P messages
}

// Finalize implements round.Round
func (r *round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Generate random nonce
	r.k = sample.Scalar(rand.Reader, r.Group())
	r.K = r.k.ActOnBase()

	// Broadcast nonce commitment
	if err := r.BroadcastMessage(out, &broadcast1{
		K: r.K,
	}); err != nil {
		return nil, err
	}

	return &round2{
		round1: r,
		nonces: make(map[party.ID]curve.Point),
	}, nil
}

// StoreBroadcastMessage implements round.BroadcastRound
func (r *round1) StoreBroadcastMessage(_ round.Message) error {
	// Messages stored in round2
	return nil
}
