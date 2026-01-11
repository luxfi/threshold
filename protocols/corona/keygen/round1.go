package keygen

import (
	"crypto/rand"
	"encoding/binary"
	"io"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/hash"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/corona/config"
	"golang.org/x/crypto/blake2b"

	realring "github.com/luxfi/corona/threshold"
)

// round1 generates key shares using real Corona and distributes commitments
type round1 struct {
	*round.Helper

	config       *config.Config
	selfIndex    int
	participants []party.ID

	// Real corona key generation results
	keyShares []*realring.KeyShare
	groupKey  *realring.GroupKey

	// Received shares from other parties
	shares map[party.ID][]byte

	// Commitment to our key material
	commitment hash.Commitment
	decommit   hash.Decommitment
}

// broadcast1 contains the polynomial commitment
type broadcast1 struct {
	round.NormalBroadcastContent

	// Commitment to the key material
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

	return nil
}

// Finalize implements round.Round
func (r *round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	n := len(r.participants)
	t := r.Threshold()

	// Generate real Corona key shares using the threshold package
	keyShares, groupKey, err := realring.GenerateKeys(t, n, rand.Reader)
	if err != nil {
		return nil, err
	}

	r.keyShares = keyShares
	r.groupKey = groupKey

	// Serialize our key share for commitment
	myShare := keyShares[r.selfIndex]
	shareData := serializeKeyShare(myShare)

	// Create commitment to our key share
	h, _ := blake2b.New256(nil)
	h.Write(shareData)
	shareHash := h.Sum(nil)

	commitment, decommit, err := r.Hash().Commit(shareHash)
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
		Helper:       r.Helper,
		config:       r.config,
		selfIndex:    r.selfIndex,
		participants: r.participants,
		keyShares:    r.keyShares,
		groupKey:     r.groupKey,
		shares:       r.shares,
		commitment:   r.commitment,
		decommit:     r.decommit,
	}, nil
}

// serializeKeyShare serializes a real corona KeyShare
func serializeKeyShare(share *realring.KeyShare) []byte {
	// Serialize the key share components
	var data []byte

	// Add index
	indexBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(indexBytes, uint32(share.Index))
	data = append(data, indexBytes...)

	// Add SkShare polynomial data
	for _, poly := range share.SkShare {
		coeffs := poly.Coeffs
		for _, modCoeffs := range coeffs {
			for _, coeff := range modCoeffs {
				coeffBytes := make([]byte, 8)
				binary.LittleEndian.PutUint64(coeffBytes, coeff)
				data = append(data, coeffBytes...)
			}
		}
	}

	return data
}

// deserializeKeyShare deserializes a key share (for receiving from other parties)
func deserializeKeyShare(data []byte, reader io.Reader) (*realring.KeyShare, error) {
	if len(data) < 4 {
		return nil, round.ErrInvalidContent
	}

	index := int(binary.LittleEndian.Uint32(data[:4]))

	// For receiving shares, we create a minimal share structure
	// The real shares are generated locally by each party
	return &realring.KeyShare{
		Index: index,
	}, nil
}
