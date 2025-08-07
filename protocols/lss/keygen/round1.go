package keygen

import (
	"crypto/rand"
	"errors"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/internal/types"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/math/sample"
	"github.com/luxfi/threshold/pkg/party"
)

// round1 generates polynomial and broadcasts commitments
type round1 struct {
	*round.Helper

	// Our polynomial for secret sharing
	poly *polynomial.Polynomial

	// Chain key for deriving randomness
	chainKey types.RID
	
	// Storage for received broadcasts
	receivedCommitments map[party.ID]map[party.ID]curve.Point
	receivedChainKeys   map[party.ID]types.RID
}

// broadcast1 contains the polynomial commitments
type broadcast1 struct {
	round.NormalBroadcastContent

	// Commitments to polynomial - we commit to g^f(i) for each party i
	// Stored as binary data for CBOR compatibility
	Commitments map[party.ID][]byte

	// Chain key commitment
	ChainKey types.RID
}

// SetCommitments converts a map of points to binary for storage
func (b *broadcast1) SetCommitments(commitments map[party.ID]curve.Point) error {
	b.Commitments = make(map[party.ID][]byte)
	for id, point := range commitments {
		data, err := point.MarshalBinary()
		if err != nil {
			return err
		}
		b.Commitments[id] = data
	}
	return nil
}

// GetCommitments converts the binary data back to points
func (b *broadcast1) GetCommitments(group curve.Curve) (map[party.ID]curve.Point, error) {
	commitments := make(map[party.ID]curve.Point)
	for id, data := range b.Commitments {
		point := group.NewPoint()
		if err := point.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		commitments[id] = point
	}
	return commitments, nil
}

// BroadcastContent implements round.BroadcastRound
func (r *round1) BroadcastContent() round.BroadcastContent {
	return &broadcast1{}
}

// Number implements round.Round
func (r *round1) Number() round.Number {
	return 1
}

// MessageContent implements round.Round
func (r *round1) MessageContent() round.Content {
	// Round1 only broadcasts, no P2P messages
	return nil
}

// RoundNumber implements round.Content
func (broadcast1) RoundNumber() round.Number {
	return 1
}

// VerifyMessage implements round.Round
func (r *round1) VerifyMessage(_ round.Message) error {
	// No P2P messages to verify
	return nil
}

// StoreMessage implements round.Round
func (r *round1) StoreMessage(_ round.Message) error {
	// No P2P messages to store
	return nil
}

// Finalize implements round.Round
func (r *round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// If we haven't generated our polynomial yet, do it now
	if r.poly == nil {
		// Generate our polynomial with random secret
		secret := sample.Scalar(rand.Reader, r.Group())
		r.poly = polynomial.NewPolynomial(r.Group(), r.Threshold()-1, secret)

		// Generate chain key
		chainKey, err := types.NewRID(rand.Reader)
		if err != nil {
			return nil, err
		}
		r.chainKey = chainKey

		// Create commitments: g^f(j) for each party j
		// This allows verification of shares later
		commitments := make(map[party.ID]curve.Point)
		for _, j := range r.PartyIDs() {
			x := j.Scalar(r.Group())
			share := r.poly.Evaluate(x)
			commitments[j] = share.ActOnBase()
		}

		// Broadcast commitments
		broadcast := &broadcast1{ChainKey: chainKey}
		if err := broadcast.SetCommitments(commitments); err != nil {
			return nil, err
		}
		if err := r.BroadcastMessage(out, broadcast); err != nil {
			return nil, err
		}
		
		// Store our own commitments
		if r.receivedCommitments == nil {
			r.receivedCommitments = make(map[party.ID]map[party.ID]curve.Point)
			r.receivedChainKeys = make(map[party.ID]types.RID)
		}
		r.receivedCommitments[r.SelfID()] = commitments
		r.receivedChainKeys[r.SelfID()] = chainKey
	}

	// Check if we have received all commitments
	// We need commitments from all N parties (including ourselves)
	if len(r.receivedCommitments) < r.N() {
		// Not ready to advance yet - return ourselves
		// This is called from finalizeInitial when we don't have all broadcasts yet
		return r, nil
	}

	// We have all commitments, create round2 with complete data
	return &round2{
		Helper:      r.Helper,
		poly:        r.poly,
		commitments: r.receivedCommitments,
		chainKeys:   r.receivedChainKeys,
		shares:      make(map[party.ID]curve.Scalar),
	}, nil
}

// StoreBroadcastMessage implements round.BroadcastRound
func (r *round1) StoreBroadcastMessage(msg round.Message) error {
	// Validate the broadcast message
	body, ok := msg.Content.(*broadcast1)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	
	// Basic validation
	if len(body.Commitments) != r.N() {
		return errors.New("wrong number of commitments")
	}
	
	// Initialize storage if needed
	if r.receivedCommitments == nil {
		r.receivedCommitments = make(map[party.ID]map[party.ID]curve.Point)
		r.receivedChainKeys = make(map[party.ID]types.RID)
	}
	
	// Convert back to map and store
	commitments, err := body.GetCommitments(r.Group())
	if err != nil {
		return err
	}
	r.receivedCommitments[msg.From] = commitments
	r.receivedChainKeys[msg.From] = body.ChainKey
	
	return nil
}
