package reshare

import (
	"errors"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/hash"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/lss/config"
)

// round3 finalizes the reshare protocol
type round3 struct {
	*round2
}

// Number implements round.Round
func (r *round3) Number() round.Number {
	return 3
}

// BroadcastContent implements round.BroadcastRound
func (r *round3) BroadcastContent() round.BroadcastContent {
	return nil // No broadcast in round 3
}

// MessageContent implements round.Round
func (r *round3) MessageContent() round.Content {
	return nil // No messages in round 3
}

// VerifyMessage implements round.Round
func (r *round3) VerifyMessage(msg round.Message) error {
	return nil // No messages to verify
}

// StoreMessage implements round.Round
func (r *round3) StoreMessage(msg round.Message) error {
	return nil // No messages to store
}

// Finalize implements round.Round
func (r *round3) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Compute our new share
	var newShare curve.Scalar
	
	if r.inNewGroup {
		// Sum shares from old parties
		newShare = r.Group().NewScalar()
		for from, share := range r.shares {
			// Only include shares from old parties
			isOldParty := false
			for _, id := range r.oldConfig.PartyIDs() {
				if id == from {
					isOldParty = true
					break
				}
			}
			if isOldParty {
				newShare = newShare.Add(share)
			}
		}
		
		// If we're also in the old group, add our self-contribution
		if r.inOldGroup {
			x := r.SelfID().Scalar(r.Group())
			selfShare := r.poly.Evaluate(x)
			newShare = newShare.Add(selfShare)
		}
	} else {
		// We're leaving the group, no new share
		return nil, errors.New("party not in new group")
	}
	
	// Build new public shares map
	publicShares := make(map[party.ID]*config.Public, len(r.newParticipants))
	for _, j := range r.newParticipants {
		publicPoint := r.Group().NewPoint()
		
		// Sum commitments from old parties
		for from, commitments := range r.commitments {
			// Only include commitments from old parties
			isOldParty := false
			for _, id := range r.oldConfig.PartyIDs() {
				if id == from {
					isOldParty = true
					break
				}
			}
			
			if isOldParty {
				if commitment, ok := commitments[j]; ok {
					publicPoint = publicPoint.Add(commitment)
				}
			}
		}
		
		publicShares[j] = &config.Public{
			ECDSA: publicPoint,
		}
	}
	
	// Compute combined chain key
	chainKeyData := make([][]byte, 0, len(r.newParticipants))
	for _, id := range r.newParticipants {
		if chainKey, ok := r.chainKeys[id]; ok {
			chainKeyData = append(chainKeyData, chainKey[:])
		}
	}
	
	// Hash all chain keys together
	h := hash.New()
	for _, data := range chainKeyData {
		h.WriteAny(data)
	}
	finalChainKey := h.Sum()
	
	// Create final RID
	ridHash := hash.New()
	ridHash.WriteAny(r.Hash())
	ridHash.WriteAny(finalChainKey)
	finalRID := ridHash.Sum()
	
	// Create new config with updated generation
	cfg := &config.Config{
		ID:         r.SelfID(),
		Group:      r.Group(),
		Threshold:  r.newThreshold,
		Generation: r.oldConfig.Generation + 1,
		ECDSA:      newShare,
		Public:     publicShares,
		ChainKey:   finalChainKey[:],
		RID:        finalRID[:],
	}
	
	// Validate the config
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	
	// Verify public key is preserved (should match old public key)
	newPublicKey, err := cfg.PublicPoint()
	if err != nil {
		return nil, err
	}
	
	oldPublicKey, err := r.oldConfig.PublicPoint()
	if err != nil {
		return nil, err
	}
	
	if !newPublicKey.Equal(oldPublicKey) {
		return nil, errors.New("public key changed during reshare")
	}
	
	return r.ResultRound(cfg), nil
}

// StoreBroadcastMessage implements round.BroadcastRound
func (r *round3) StoreBroadcastMessage(msg round.Message) error {
	return nil // No broadcast messages in round 3
}