package keygen

import (
	"errors"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/hash"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/lss/config"
)

// round3 finalizes the keygen protocol
type round3 struct {
	*round2
}

// BroadcastContent implements round.BroadcastRound
func (r *round3) BroadcastContent() round.BroadcastContent {
	return nil // No broadcast in round 3
}

// Number implements round.Round
func (r *round3) Number() round.Number {
	return 3
}

// MessageContent implements round.Round
func (r *round3) MessageContent() round.Content {
	return nil // No messages in round 3
}

// VerifyMessage implements round.Round
func (r *round3) VerifyMessage(_ round.Message) error {
	// No messages to verify
	return nil
}

// StoreMessage implements round.Round
func (r *round3) StoreMessage(_ round.Message) error {
	// No messages to store
	return nil
}

// Finalize implements round.Round
func (r *round3) Finalize(_ chan<- *round.Message) (round.Session, error) {
	// Verify we have shares from all parties
	if len(r.shares) != r.N() {
		return nil, errors.New("missing shares from some parties")
	}

	// Compute our final ECDSA share: sum of all shares received
	ecdsaShare := r.Group().NewScalar()
	for _, share := range r.shares {
		ecdsaShare = ecdsaShare.Add(share)
	}

	// Build public shares map
	// The public share for party j is the sum of all g^f_i(j)
	publicShares := make(map[party.ID]*config.Public, r.N())
	for _, j := range r.PartyIDs() {
		publicPoint := r.Group().NewPoint()
		for _, commitments := range r.commitments {
			if commitment, ok := commitments[j]; ok {
				publicPoint = publicPoint.Add(commitment)
			}
		}
		publicShares[j] = &config.Public{
			ECDSA: publicPoint,
		}
	}

	// Compute combined chain key and RID
	chainKeyData := make([][]byte, 0, r.N())
	for _, id := range r.PartyIDs() {
		if chainKey, ok := r.chainKeys[id]; ok {
			chainKeyData = append(chainKeyData, chainKey[:])
		}
	}

	// Hash all chain keys together for final chain key
	h := hash.New()
	for _, data := range chainKeyData {
		_ = h.WriteAny(data)
	}
	finalChainKey := h.Sum()

	// Create final RID by hashing session ID and chain key
	ridHash := hash.New()
	_ = ridHash.WriteAny(r.Hash())
	_ = ridHash.WriteAny(finalChainKey)
	finalRID := ridHash.Sum()

	// Create the final config
	cfg := &config.Config{
		ID:         r.SelfID(),
		Group:      r.Group(),
		Threshold:  r.Threshold(),
		Generation: 0, // Initial generation
		ECDSA:      ecdsaShare,
		Public:     publicShares,
		ChainKey:   finalChainKey[:],
		RID:        finalRID[:],
	}

	// Validate the config before returning
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Verify that the public key can be recovered
	if _, err := cfg.PublicPoint(); err != nil {
		return nil, errors.New("failed to recover public key")
	}

	return r.ResultRound(cfg), nil
}

// StoreBroadcastMessage implements round.BroadcastRound
func (r *round3) StoreBroadcastMessage(_ round.Message) error {
	// No broadcast messages in round 3
	return nil
}

