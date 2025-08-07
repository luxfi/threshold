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
	Commitments map[party.ID]curve.Point

	// Chain key commitment
	ChainKey types.RID
}

// BroadcastContent implements round.BroadcastRound
func (r *round1) BroadcastContent() round.BroadcastContent {
	return &broadcast1{}
}

// Number implements round.Round
func (r *round1) Number() round.Number {
	return 1
}

// message1 is a dummy message to work around handler initialization issue
type message1 struct{}

func (message1) RoundNumber() round.Number { return 1 }

// MessageContent implements round.Round
func (r *round1) MessageContent() round.Content {
	// Return a dummy message type to prevent immediate finalization
	// This works around the issue where the handler thinks round1
	// doesn't expect any messages and finalizes immediately
	return &message1{}
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

	// Send dummy P2P messages to work around handler issue
	// The handler won't finalize round1 until it receives these
	for _, id := range r.OtherPartyIDs() {
		if err := r.SendMessage(out, &message1{}, id); err != nil {
			return nil, err
		}
	}

	// Broadcast commitments
	if err := r.BroadcastMessage(out, &broadcast1{
		Commitments: commitments,
		ChainKey:    chainKey,
	}); err != nil {
		return nil, err
	}

	// Initialize storage for round2 with ALL commitments
	commitmentStore := r.receivedCommitments
	if commitmentStore == nil {
		commitmentStore = make(map[party.ID]map[party.ID]curve.Point)
	}
	chainKeyStore := r.receivedChainKeys
	if chainKeyStore == nil {
		chainKeyStore = make(map[party.ID]types.RID)
	}
	
	// Store our own commitments and chain key
	commitmentStore[r.SelfID()] = commitments
	chainKeyStore[r.SelfID()] = chainKey

	return &round2{
		round1:      r,
		commitments: commitmentStore,
		chainKeys:   chainKeyStore,
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
	
	// Store the commitments and chain key
	r.receivedCommitments[msg.From] = body.Commitments
	r.receivedChainKeys[msg.From] = body.ChainKey
	
	return nil
}
