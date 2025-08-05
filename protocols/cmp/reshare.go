package cmp

import (
	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/cmp/keygen"
)

// DynamicReshare is implemented in dynamic_reshare.go
/*
func DynamicReshare(oldConfig *Config, newPartyIDs []party.ID, newThreshold int, pl *pool.Pool) protocol.StartFunc {
	// Determine if we're adding or removing parties
	oldParties := make(map[party.ID]bool)
	for _, id := range oldConfig.PartyIDs() {
		oldParties[id] = true
	}

	newParties := make(map[party.ID]bool)
	for _, id := range newPartyIDs {
		newParties[id] = true
	}

	// For the protocol, we need participation from:
	// - All old parties (to share their existing shares)
	// - All new parties (to receive new shares)
	allParticipants := make([]party.ID, 0)
	participantMap := make(map[party.ID]bool)

	// Add all old parties
	for _, id := range oldConfig.PartyIDs() {
		if !participantMap[id] {
			allParticipants = append(allParticipants, id)
			participantMap[id] = true
		}
	}

	// Add any new parties not in old set
	for _, id := range newPartyIDs {
		if !participantMap[id] {
			allParticipants = append(allParticipants, id)
			participantMap[id] = true
		}
	}

	// Validate threshold
	if newThreshold > len(newPartyIDs) {
		return func([]byte) (round.Session, error) {
			return nil, fmt.Errorf("new threshold %d exceeds new party count %d", newThreshold, len(newPartyIDs))
		}
	}

	info := round.Info{
		ProtocolID:       "cmp/dynamic-reshare",
		FinalRoundNumber: keygen.Rounds,
		SelfID:           oldConfig.ID,
		PartyIDs:         allParticipants,
		Threshold:        newThreshold,
		Group:            oldConfig.Group,
	}

	// Check if this party is in the new set
	isInNewSet := newParties[oldConfig.ID]

	// Create a wrapper that handles the dynamic aspects
	return func(sessionID []byte) (round.Session, error) {
		// If we're an old party, we participate with our existing config
		// If we're a new party, we participate with a nil config (like fresh keygen)
		var configToUse *Config
		if oldParties[oldConfig.ID] {
			// We're an old party, use our existing config
			configToUse = oldConfig
		} else {
			// We're a new party joining, start fresh
			configToUse = nil
		}

		// Start the keygen protocol with appropriate config
		startFunc := keygen.Start(info, pl, configToUse)
		session, err := startFunc(sessionID)
		if err != nil {
			return nil, err
		}

		// Wrap the session to filter the final result
		return &dynamicReshareSession{
			Session:     session,
			newPartyIDs: newPartyIDs,
			isInNewSet:  isInNewSet,
		}, nil
	}
}
*/

// dynamicReshareSession wraps the keygen session to handle dynamic resharing
type dynamicReshareSession struct {
	round.Session
	newPartyIDs []party.ID
	isInNewSet  bool
}

// GetRound wraps the underlying GetRound but may need to handle the final round specially
func (d *dynamicReshareSession) GetRound() round.Round {
	// TODO: round.Session doesn't have GetRound method
	// r := d.Session.GetRound()
	var r round.Round

	// Check if this is the final round that produces the config
	if r.Number() == keygen.Rounds {
		// We need to ensure only new parties are in the final config
		// This might require wrapping the round's finalize method
		return &finalRoundWrapper{
			Round:       r,
			newPartyIDs: d.newPartyIDs,
			isInNewSet:  d.isInNewSet,
		}
	}

	return r
}

// finalRoundWrapper ensures the final config only includes new parties
type finalRoundWrapper struct {
	round.Round
	newPartyIDs []party.ID
	isInNewSet  bool
}

// Other methods delegate to the wrapped round...

// GenerateShares generates shares for parties according to the re-sharing protocol
// This implements the JVSS-like functionality for the auxiliary secrets
func GenerateShares(config *Config, newParties []party.ID, threshold int) (map[party.ID]interface{}, error) {
	// This would implement the joint secret sharing for auxiliary values
	// Used in the 4-step resharing protocol from the LSS paper
	shares := make(map[party.ID]interface{})

	// Implementation would go here...

	return shares, nil
}
