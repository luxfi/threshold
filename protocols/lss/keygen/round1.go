package keygen

import (
	"crypto/rand"
	"errors"
	"sync"

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

	// Storage for received broadcasts - using sync.Map for thread safety
	receivedCommitments sync.Map // map[party.ID]map[party.ID]curve.Point
	receivedChainKeys   sync.Map // map[party.ID]types.RID

	// Track if we've already generated our values to prevent regeneration
	generated bool
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
	// Only generate values once to prevent different values on repeated calls
	if !r.generated {
		r.generated = true

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

		// Store our own commitments using sync.Map
		r.receivedCommitments.Store(r.SelfID(), commitments)
		r.receivedChainKeys.Store(r.SelfID(), chainKey)
	}

	// Check if we have received all commitments
	// We need commitments from all N parties (including ourselves)
	// Count the number of stored entries
	count := 0
	r.receivedCommitments.Range(func(_, _ interface{}) bool {
		count++
		return true
	})

	if count < r.N() {
		// Not ready to advance yet - return ourselves
		// This is called from finalizeInitial when we don't have all broadcasts yet
		return r, nil
	}

	// We have all commitments, convert sync.Map back to regular map for round2
	commitments := make(map[party.ID]map[party.ID]curve.Point)
	chainKeys := make(map[party.ID]types.RID)

	r.receivedCommitments.Range(func(key, value interface{}) bool {
		id := key.(party.ID)
		commitments[id] = value.(map[party.ID]curve.Point)
		return true
	})

	r.receivedChainKeys.Range(func(key, value interface{}) bool {
		id := key.(party.ID)
		chainKeys[id] = value.(types.RID)
		return true
	})

	// Create round2 with complete data
	return &round2{
		Helper:      r.Helper,
		poly:        r.poly,
		commitments: commitments,
		chainKeys:   chainKeys,
		shares:      sync.Map{}, // Initialize as sync.Map
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

	// Convert back to map and store
	commitments, err := body.GetCommitments(r.Group())
	if err != nil {
		return err
	}

	// Store using sync.Map for thread safety
	r.receivedCommitments.Store(msg.From, commitments)
	r.receivedChainKeys.Store(msg.From, body.ChainKey)

	return nil
}
