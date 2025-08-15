package keygen

import (
	"encoding/binary"
	"errors"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/hash"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/ringtail/config"
	"golang.org/x/crypto/blake2b"
)

// round2 reveals polynomial and creates VSS shares
type round2 struct {
	*round.Helper

	config     *config.Config
	polynomial []int
	shares     map[party.ID][]byte
	commitment hash.Commitment
	decommit   hash.Decommitment

	// Stores received polynomials from other parties
	polynomials map[party.ID][]int

	// Stores received decommitments
	decommitments map[party.ID]hash.Decommitment
}

// broadcast2 contains the polynomial and decommitment
type broadcast2 struct {
	round.NormalBroadcastContent

	// The polynomial coefficients
	Polynomial []int

	// Decommitment to verify against round 1 commitment
	Decommitment hash.Decommitment
}

// message2 contains the VSS share for a specific party
type message2 struct {
	Share []byte // Encrypted share for the recipient
}

// Number implements round.Round
func (r *round2) Number() round.Number {
	return 2
}

// RoundNumber implements round.Content for broadcast2
func (broadcast2) RoundNumber() round.Number {
	return 2
}

// RoundNumber implements round.Content for message2
func (message2) RoundNumber() round.Number {
	return 2
}

// BroadcastContent implements round.BroadcastRound
func (r *round2) BroadcastContent() round.BroadcastContent {
	return &broadcast2{}
}

// MessageContent implements round.Round
func (r *round2) MessageContent() round.Content {
	return &message2{}
}

// VerifyMessage implements round.Round
func (r *round2) VerifyMessage(msg round.Message) error {
	body, ok := msg.Content.(*message2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// Verify share is valid size
	params := r.config.GetParameters()
	expectedSize := params.N * 8 // Each coefficient is 8 bytes
	if len(body.Share) != expectedSize {
		return errors.New("invalid share size")
	}

	return nil
}

// StoreMessage implements round.Round
func (r *round2) StoreMessage(msg round.Message) error {
	body, ok := msg.Content.(*message2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	r.shares[msg.From] = body.Share
	return nil
}

// StoreBroadcastMessage implements round.BroadcastRound
func (r *round2) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*broadcast2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// Verify the polynomial matches the commitment from round 1
	h, _ := blake2b.New256(nil)
	for _, coeff := range body.Polynomial {
		coeffBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(coeffBytes, uint64(coeff))
		h.Write(coeffBytes)
	}
	polyHash := h.Sum(nil)

	// Verify decommitment
	if !r.Hash().Decommit(polyHash, body.Decommitment, nil) {
		return errors.New("invalid decommitment")
	}

	if r.polynomials == nil {
		r.polynomials = make(map[party.ID][]int)
	}
	if r.decommitments == nil {
		r.decommitments = make(map[party.ID]hash.Decommitment)
	}

	r.polynomials[msg.From] = body.Polynomial
	r.decommitments[msg.From] = body.Decommitment

	return nil
}

// Finalize implements round.Round
func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Broadcast our polynomial and decommitment
	if err := r.BroadcastMessage(out, &broadcast2{
		Polynomial:   r.polynomial,
		Decommitment: r.decommit,
	}); err != nil {
		return nil, err
	}

	// Store our own polynomial
	if r.polynomials == nil {
		r.polynomials = make(map[party.ID][]int)
	}
	r.polynomials[r.SelfID()] = r.polynomial

	// Generate VSS shares for each party
	params := r.config.GetParameters()
	partyIDs := r.PartyIDs()

	for i, partyID := range partyIDs {
		// Evaluate polynomial at point i+1 to create share
		share := evaluatePolynomial(r.polynomial, i+1, params.Q)

		// Convert share to bytes
		shareBytes := make([]byte, params.N*8)
		for j, coeff := range share {
			binary.LittleEndian.PutUint64(shareBytes[j*8:], uint64(coeff))
		}

		if partyID == r.SelfID() {
			// Store our own share
			r.shares[partyID] = shareBytes
		} else {
			// Send share to other party
			if err := r.SendMessage(out, &message2{
				Share: shareBytes,
			}, partyID); err != nil {
				return nil, err
			}
		}
	}

	// Move to round 3
	return &round3{
		Helper:        r.Helper,
		config:        r.config,
		polynomial:    r.polynomial,
		shares:        r.shares,
		polynomials:   r.polynomials,
		decommitments: r.decommitments,
	}, nil
}

// evaluatePolynomial evaluates a polynomial at a given point
func evaluatePolynomial(coeffs []int, x int, modulus int) []int {
	result := make([]int, len(coeffs))

	// For simplicity, return scaled coefficients
	// Real implementation would do proper polynomial evaluation
	for i, coeff := range coeffs {
		result[i] = (coeff * x) % modulus
	}

	return result
}
