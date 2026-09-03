package reshare

import (
	"crypto/rand"
	"errors"
	"sort"

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
	*round.Base

	oldConfig       *config.Config
	newParticipants []party.ID
	newThreshold    int
	inOldGroup      bool
	inNewGroup      bool

	// Polynomial for resharing (only for old parties)
	poly *polynomial.Polynomial

	// Chain key for new randomness
	chainKey types.RID

	// What the round-1 broadcast carries, filled by StoreBroadcastMessage.
	//
	// These live on round 1 and not on round 2 because broadcast1 declares
	// RoundNumber 1, so the handler routes it HERE: a round 2 that owned them
	// would never see a commitment, and round 2's verification would refuse
	// every share with "missing commitments from sender". round2 embeds this
	// round, so reading them through the embed is the same map.
	commitments map[party.ID]map[party.ID][]byte
	chainKeys   map[party.ID]types.RID
}

// broadcast1 contains reshare commitments
type broadcast1 struct {
	round.NormalBroadcastContent

	// Commitments to reshare polynomial — g^f(j) for each new party j, encoded
	// as binary because curve.Point is an INTERFACE and CBOR has no concrete
	// type to decode one into: a broadcast carrying it fails on the receiving
	// side with "cannot unmarshal byte string into ... of type curve.Point",
	// which aborts the protocol before round 2 can begin. keygen's message2
	// carries its share as []byte for the same reason.
	Commitments map[party.ID][]byte

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
func (r *round1) VerifyMessage(_ round.Message) error {
	return nil // No P2P messages
}

// StoreMessage implements round.Round
func (r *round1) StoreMessage(_ round.Message) error {
	return nil // No P2P messages
}

// Finalize implements round.Round
func (r *round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Kept so round 2 can seed this party's OWN contribution: a broadcast is
	// never delivered back to its sender (Message.IsFor is false when From is
	// the recipient), so nothing else would put these in the map. Round 3 sums
	// every old party's commitments to build the new public shares while
	// adding this party's own SHARE separately — so without this the public
	// shares are one contribution short of the private ones and the key check
	// refuses a reshare that was otherwise correct.
	var own map[party.ID][]byte

	// Only old parties generate polynomials
	if r.inOldGroup {
		// The constant term is this party's share WEIGHTED BY ITS LAGRANGE
		// COEFFICIENT over the old committee, not the bare share.
		//
		// Resharing preserves the key because the new shares sum to the old
		// secret, and the old secret is Σ λⱼ·xⱼ over the committee — not Σ xⱼ.
		// Seeding each polynomial with the bare xⱼ reshares Σ xⱼ instead, which
		// is a different secret and therefore a different public key, and round
		// 3 refuses it with "public key changed during reshare". The coefficient
		// depends on the SET of contributing parties and not their order, so
		// every party computes the same one from the same committee.
		contributors := r.oldConfig.PartyIDs()
		sort.Slice(contributors, func(i, j int) bool { return contributors[i] < contributors[j] })
		lambda, ok := polynomial.Lagrange(r.Group(), contributors)[r.SelfID()]
		if !ok {
			return nil, errors.New("reshare: this party is not in the old committee it is resharing from")
		}
		weighted := r.Group().NewScalar().Set(lambda).Mul(r.oldConfig.ECDSA)
		r.poly = polynomial.NewPolynomial(r.Group(), r.newThreshold-1, weighted)

		// Generate new chain key
		chainKey, err := types.NewRID(rand.Reader)
		if err != nil {
			return nil, err
		}
		r.chainKey = chainKey

		// Create commitments for each new party
		commitments := make(map[party.ID][]byte)
		own = commitments
		for _, j := range r.newParticipants {
			x := j.Scalar(r.Group())
			b, err := r.poly.Evaluate(x).ActOnBase().MarshalBinary()
			if err != nil {
				return nil, err
			}
			commitments[j] = b
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
		commitments := make(map[party.ID][]byte)
		own = commitments
		for _, j := range r.newParticipants {
			b, err := r.Group().NewPoint().MarshalBinary()
			if err != nil {
				return nil, err
			}
			commitments[j] = b // identity
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

	// This party's own contribution: a broadcast is never delivered back to its
	// sender, so nothing else puts these in the map, and round 3 sums every old
	// party's commitments while adding this party's own SHARE separately.
	r.commitments[r.SelfID()] = own
	r.chainKeys[r.SelfID()] = r.chainKey

	return &round2{
		round1: r,
		shares: make(map[party.ID]curve.Scalar),
	}, nil
}

// StoreBroadcastMessage implements round.BroadcastRound
func (r *round1) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*broadcast1)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	if body.Generation != r.oldConfig.Generation+1 {
		return errors.New("wrong generation in broadcast")
	}
	r.commitments[msg.From] = body.Commitments
	r.chainKeys[msg.From] = body.ChainKey
	return nil
}
