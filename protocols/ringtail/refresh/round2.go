package refresh

import (
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/hash"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/ringtail/config"
	"golang.org/x/crypto/blake2b"
)

// refreshRound2 shares refresh polynomials
type refreshRound2 struct {
	*round.Helper
	config          *config.Config
	newParticipants []party.ID
	newThreshold    int
	shares          map[party.ID][]byte
	newPolynomial   []int
	decommit        hash.Decommitment

	// Received refresh shares
	refreshShares map[party.ID][]byte
}

// refreshBroadcast2 reveals the refresh polynomial
type refreshBroadcast2 struct {
	round.NormalBroadcastContent
	Polynomial   []int
	Decommitment hash.Decommitment
}

// refreshMessage2 contains encrypted refresh share
type refreshMessage2 struct {
	RefreshShare []byte
}

// Number implements round.Round
func (r *refreshRound2) Number() round.Number {
	return 2
}

// RoundNumber implements round.Content
func (refreshBroadcast2) RoundNumber() round.Number {
	return 2
}

// RoundNumber implements round.Content
func (refreshMessage2) RoundNumber() round.Number {
	return 2
}

// BroadcastContent implements round.BroadcastRound
func (r *refreshRound2) BroadcastContent() round.BroadcastContent {
	return &refreshBroadcast2{}
}

// MessageContent implements round.Round
func (r *refreshRound2) MessageContent() round.Content {
	return &refreshMessage2{}
}

// VerifyMessage implements round.Round
func (r *refreshRound2) VerifyMessage(msg round.Message) error {
	body, ok := msg.Content.(*refreshMessage2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	params := r.config.GetParameters()
	expectedSize := params.N * 8
	if len(body.RefreshShare) != expectedSize {
		return errors.New("invalid refresh share size")
	}

	return nil
}

// StoreMessage implements round.Round
func (r *refreshRound2) StoreMessage(msg round.Message) error {
	body, ok := msg.Content.(*refreshMessage2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if r.refreshShares == nil {
		r.refreshShares = make(map[party.ID][]byte)
	}
	r.refreshShares[msg.From] = body.RefreshShare
	return nil
}

// StoreBroadcastMessage implements round.BroadcastRound
func (r *refreshRound2) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*refreshBroadcast2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// Verify decommitment matches polynomial
	if !verifyPolynomialCommitment(body.Polynomial, body.Decommitment, *r.Hash()) {
		return errors.New("invalid polynomial decommitment")
	}

	return nil
}

// Finalize implements round.Round
func (r *refreshRound2) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Broadcast our refresh polynomial
	if err := r.BroadcastMessage(out, &refreshBroadcast2{
		Polynomial:   r.newPolynomial,
		Decommitment: r.decommit,
	}); err != nil {
		return nil, err
	}

	// Generate refresh shares for each new participant
	params := r.config.GetParameters()
	for i, partyID := range r.newParticipants {
		share := evaluateRefreshPolynomial(r.newPolynomial, i+1, params.Q)

		shareBytes := make([]byte, params.N*8)
		for j, coeff := range share {
			binary.LittleEndian.PutUint64(shareBytes[j*8:], uint64(coeff))
		}

		if partyID == r.SelfID() {
			if r.refreshShares == nil {
				r.refreshShares = make(map[party.ID][]byte)
			}
			r.refreshShares[partyID] = shareBytes
		} else {
			if err := r.SendMessage(out, &refreshMessage2{
				RefreshShare: shareBytes,
			}, partyID); err != nil {
				return nil, err
			}
		}
	}

	// Move to round 3
	return &refreshRound3{
		Helper:          r.Helper,
		config:          r.config,
		newParticipants: r.newParticipants,
		newThreshold:    r.newThreshold,
		refreshShares:   r.refreshShares,
	}, nil
}

// Helper functions

func generateRefreshPolynomial(n, q int) []int {
	poly := make([]int, n)
	for i := 0; i < n; i++ {
		var buf [8]byte
		rand.Read(buf[:])
		poly[i] = int(binary.LittleEndian.Uint64(buf[:]) % uint64(q))
	}
	// First coefficient should be 0 for refresh (maintains same secret)
	poly[0] = 0
	return poly
}

func createPolynomialCommitment(poly []int, hasher hash.Hash) ([]byte, hash.Decommitment) {
	h, _ := blake2b.New256(nil)
	for _, coeff := range poly {
		coeffBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(coeffBytes, uint64(coeff))
		h.Write(coeffBytes)
	}
	polyHash := h.Sum(nil)

	commitment, decommit, _ := hasher.Commit(polyHash)
	return commitment, decommit
}

func verifyPolynomialCommitment(poly []int, decommit hash.Decommitment, hasher hash.Hash) bool {
	h, _ := blake2b.New256(nil)
	for _, coeff := range poly {
		coeffBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(coeffBytes, uint64(coeff))
		h.Write(coeffBytes)
	}
	polyHash := h.Sum(nil)

	return hasher.Decommit(polyHash, decommit, nil)
}

func evaluateRefreshPolynomial(coeffs []int, x int, modulus int) []int {
	result := make([]int, len(coeffs))
	for i, coeff := range coeffs {
		result[i] = (coeff * x) % modulus
	}
	return result
}
