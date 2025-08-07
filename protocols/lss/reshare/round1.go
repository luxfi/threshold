package reshare

import (
	"crypto/rand"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/internal/types"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/math/sample"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/lss/config"
)

// round1 initiates resharing by generating new polynomial shares
type round1 struct {
	*round.Helper
	
	oldConfig        *config.Config
	newParticipants  []party.ID
	newThreshold     int
	inOldGroup       bool
	inNewGroup       bool
	
	// Polynomial for resharing (only for old parties)
	poly *polynomial.Polynomial
	
	// Chain key for new randomness
	chainKey types.RID
}

// broadcast1 contains reshare commitments
type broadcast1 struct {
	round.NormalBroadcastContent
	
	// Commitments to reshare polynomial - g^f(j) for each new party j
	Commitments map[party.ID]curve.Point
	
	// Chain key for randomness
	ChainKey types.RID
	
	// Generation number
	Generation uint64
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
func (r *round1) VerifyMessage(msg round.Message) error {
	return nil // No P2P messages
}

// StoreMessage implements round.Round
func (r *round1) StoreMessage(msg round.Message) error {
	return nil // No P2P messages
}

// Finalize implements round.Round
func (r *round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Only old parties generate polynomials
	if r.inOldGroup {
		// Generate polynomial with our current share as constant term
		// This preserves the group's public key
		r.poly = polynomial.NewPolynomial(r.Group(), r.newThreshold-1, r.oldConfig.ECDSA)
		
		// Generate new chain key
		chainKey, err := types.NewRID(rand.Reader)
		if err != nil {
			return nil, err
		}
		r.chainKey = chainKey
		
		// Create commitments for each new party
		commitments := make(map[party.ID]curve.Point)
		for _, j := range r.newParticipants {
			x := j.Scalar(r.Group())
			share := r.poly.Evaluate(x)
			commitments[j] = share.ActOnBase()
		}
		
		// Broadcast commitments
		if err := r.BroadcastMessage(out, &broadcast1{
			Commitments: commitments,
			ChainKey:    chainKey,
			Generation:  r.oldConfig.Generation + 1,
		}); err != nil {
			return nil, err
		}
	} else {
		// New parties just generate a random polynomial for blinding
		secret := sample.Scalar(rand.Reader, r.Group())
		r.poly = polynomial.NewPolynomial(r.Group(), r.newThreshold-1, secret)
		
		// Generate chain key
		chainKey, err := types.NewRID(rand.Reader)
		if err != nil {
			return nil, err
		}
		r.chainKey = chainKey
		
		// Create dummy commitments (new parties don't contribute to resharing)
		commitments := make(map[party.ID]curve.Point)
		for _, j := range r.newParticipants {
			commitments[j] = r.Group().NewPoint() // Identity element
		}
		
		// Broadcast empty commitments 
		if err := r.BroadcastMessage(out, &broadcast1{
			Commitments: commitments,
			ChainKey:    chainKey,
			Generation:  r.oldConfig.Generation + 1,
		}); err != nil {
			return nil, err
		}
	}
	
	return &round2{
		round1:      r,
		commitments: make(map[party.ID]map[party.ID]curve.Point),
		chainKeys:   make(map[party.ID]types.RID),
		shares:      make(map[party.ID]curve.Scalar),
	}, nil
}

// StoreBroadcastMessage implements round.BroadcastRound
func (r *round1) StoreBroadcastMessage(msg round.Message) error {
	// Messages stored in round2
	return nil
}