package keygen

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/hash"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/ringtail/config"
	"golang.org/x/crypto/blake2b"
)

// round1 generates lattice polynomial and broadcasts commitments
type round1 struct {
	*round.Helper

	config *config.Config

	// Our lattice polynomial coefficients
	polynomial []int

	// Received shares from other parties
	shares map[party.ID][]byte

	// Commitment to our polynomial
	commitment hash.Commitment

	// Decommitment data
	decommit hash.Decommitment
}

// broadcast1 contains the polynomial commitment
type broadcast1 struct {
	round.NormalBroadcastContent

	// Commitment to the polynomial
	Commitment hash.Commitment
}

// Number implements round.Round
func (r *round1) Number() round.Number {
	return 1
}

// RoundNumber implements round.Content
func (broadcast1) RoundNumber() round.Number {
	return 1
}

// BroadcastContent implements round.BroadcastRound
func (r *round1) BroadcastContent() round.BroadcastContent {
	return &broadcast1{}
}

// MessageContent implements round.Round
func (r *round1) MessageContent() round.Content {
	return nil // Round 1 only broadcasts
}

// VerifyMessage implements round.Round
func (r *round1) VerifyMessage(_ round.Message) error {
	return nil // No P2P messages in round 1
}

// StoreMessage implements round.Round
func (r *round1) StoreMessage(_ round.Message) error {
	return nil // No P2P messages in round 1
}

// StoreBroadcastMessage implements round.BroadcastRound
func (r *round1) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*broadcast1)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// Validate commitment
	if err := body.Commitment.Validate(); err != nil {
		return err
	}

	// Store for later verification
	// In real implementation, we'd store the commitment
	// to verify against the polynomial revealed later

	return nil
}

// Finalize implements round.Round
func (r *round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Generate random lattice polynomial
	params := r.config.GetParameters()
	r.polynomial = make([]int, params.N)

	// Generate random coefficients modulo Q
	for i := 0; i < params.N; i++ {
		var buf [8]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return nil, err
		}
		r.polynomial[i] = int(binary.LittleEndian.Uint64(buf[:]) % uint64(params.Q))
	}

	// Create commitment to polynomial
	h, _ := blake2b.New256(nil)
	for _, coeff := range r.polynomial {
		coeffBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(coeffBytes, uint64(coeff))
		h.Write(coeffBytes)
	}
	polyHash := h.Sum(nil)

	// Create commitment and decommitment
	commitment, decommit, err := r.Hash().Commit(polyHash)
	if err != nil {
		return nil, err
	}
	r.commitment = commitment
	r.decommit = decommit

	// Broadcast commitment
	if err := r.BroadcastMessage(out, &broadcast1{
		Commitment: commitment,
	}); err != nil {
		return nil, err
	}

	// Move to round 2
	return &round2{
		Helper:     r.Helper,
		config:     r.config,
		polynomial: r.polynomial,
		shares:     r.shares,
		commitment: r.commitment,
		decommit:   r.decommit,
	}, nil
}
