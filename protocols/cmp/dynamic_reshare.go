package cmp

import (
	"fmt"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/cmp/config"
	"github.com/luxfi/threshold/protocols/cmp/keygen"
)

// DynamicReshare enables adding or removing parties from the threshold scheme
// while maintaining the same ECDSA public key. This builds on top of the
// existing CMP refresh mechanism.
//
// The protocol works as follows:
// 1. All old parties and new parties participate together
// 2. Old parties use their existing shares (with f_i(0) = 0 for refresh)
// 3. New parties start fresh (as if doing initial keygen)
// 4. The result is a new sharing among only the new party set
//
// Parameters:
// - config: Current configuration (must be held by an old party)
// - newParties: The desired set of parties after resharing
// - newThreshold: The desired threshold after resharing
// - pl: Pool for parallelization
//
// Returns *cmp.Config with shares for the new party set
func DynamicReshare(config *Config, newParties []party.ID, newThreshold int, pl *pool.Pool) protocol.StartFunc {
	// Validate inputs
	if newThreshold > len(newParties) {
		return func([]byte) (round.Session, error) {
			return nil, fmt.Errorf("threshold %d exceeds party count %d", newThreshold, len(newParties))
		}
	}

	// Determine old vs new parties
	oldPartySet := make(map[party.ID]bool)
	for _, p := range config.PartyIDs() {
		oldPartySet[p] = true
	}

	newPartySet := make(map[party.ID]bool)
	for _, p := range newParties {
		newPartySet[p] = true
	}

	// All parties must participate in the resharing protocol
	allParticipants := make([]party.ID, 0)
	seen := make(map[party.ID]bool)

	// Add all old parties (they share their existing shares)
	for _, p := range config.PartyIDs() {
		if !seen[p] {
			allParticipants = append(allParticipants, p)
			seen[p] = true
		}
	}

	// Add new parties that aren't in the old set
	for _, p := range newParties {
		if !seen[p] {
			allParticipants = append(allParticipants, p)
			seen[p] = true
		}
	}

	// Create the round info for the protocol
	info := round.Info{
		ProtocolID:       "cmp/dynamic-reshare",
		FinalRoundNumber: keygen.Rounds,
		SelfID:           config.ID,
		PartyIDs:         allParticipants,
		Threshold:        newThreshold,
		Group:            config.Group,
	}

	return func(sessionID []byte) (round.Session, error) {
		// Determine our role
		isOldParty := oldPartySet[config.ID]
		isNewParty := newPartySet[config.ID]

		if !isOldParty && !isNewParty {
			return nil, fmt.Errorf("party %s not in old or new party set", config.ID)
		}

		// Old parties that are staying use their config for refresh
		// Old parties that are leaving also use their config (they help but won't be in final set)
		// New parties joining start fresh with nil config
		var startConfig *Config
		if isOldParty {
			startConfig = config
		} else {
			startConfig = nil
		}

		// Start the underlying keygen/refresh protocol
		baseStart := keygen.Start(info, pl, startConfig)
		baseSession, err := baseStart(sessionID)
		if err != nil {
			return nil, err
		}

		// Wrap the session to filter results appropriately
		return &dynamicReshareWrapper{
			Session:        baseSession,
			newParties:     newParties,
			newPartySet:    newPartySet,
			isNewParty:     isNewParty,
			originalConfig: config,
		}, nil
	}
}

// dynamicReshareWrapper wraps the base keygen session to handle dynamic aspects
type dynamicReshareWrapper struct {
	round.Session
	newParties     []party.ID
	newPartySet    map[party.ID]bool
	isNewParty     bool
	originalConfig *Config
}

// Result filters the output to ensure proper party membership
func (w *dynamicReshareWrapper) Result() (interface{}, error) {
	// Get the base result
	result, err := w.Session.Result()
	if err != nil {
		return nil, err
	}

	// If we're not in the new party set, we shouldn't have a result
	if !w.isNewParty {
		return nil, nil
	}

	// Cast to config and filter parties
	newConfig, ok := result.(*Config)
	if !ok {
		return nil, fmt.Errorf("unexpected result type: %T", result)
	}

	// Filter the public shares to only include new parties
	filteredPublic := make(map[party.ID]*config.Public)
	for id, pub := range newConfig.Public {
		if w.newPartySet[id] {
			filteredPublic[id] = pub
		}
	}
	newConfig.Public = filteredPublic

	return newConfig, nil
}

// AddParties is a convenience function to add new parties to an existing scheme
func AddParties(config *Config, partiesToAdd []party.ID, pl *pool.Pool) protocol.StartFunc {
	// Combine existing parties with new ones
	newParties := append(config.PartyIDs(), partiesToAdd...)
	
	// Keep the same threshold
	return DynamicReshare(config, newParties, config.Threshold, pl)
}

// RemoveParties is a convenience function to remove parties from an existing scheme
func RemoveParties(config *Config, partiesToRemove []party.ID, newThreshold int, pl *pool.Pool) protocol.StartFunc {
	// Create a set of parties to remove for efficient lookup
	removeSet := make(map[party.ID]bool)
	for _, p := range partiesToRemove {
		removeSet[p] = true
	}

	// Filter out the parties to remove
	newParties := make([]party.ID, 0)
	for _, p := range config.PartyIDs() {
		if !removeSet[p] {
			newParties = append(newParties, p)
		}
	}

	// Validate new threshold
	if newThreshold > len(newParties) {
		// Adjust threshold if necessary
		newThreshold = len(newParties)
	}

	return DynamicReshare(config, newParties, newThreshold, pl)
}

// ChangeThreshold modifies only the threshold while keeping the same parties
func ChangeThreshold(config *Config, newThreshold int, pl *pool.Pool) protocol.StartFunc {
	return DynamicReshare(config, config.PartyIDs(), newThreshold, pl)
}

// MigrateParties atomically removes some parties and adds others
func MigrateParties(config *Config, removeParties, addParties []party.ID, newThreshold int, pl *pool.Pool) protocol.StartFunc {
	// Create remove set
	removeSet := make(map[party.ID]bool)
	for _, p := range removeParties {
		removeSet[p] = true
	}

	// Start with existing parties minus removed ones
	newParties := make([]party.ID, 0)
	for _, p := range config.PartyIDs() {
		if !removeSet[p] {
			newParties = append(newParties, p)
		}
	}

	// Add new parties
	newParties = append(newParties, addParties...)

	return DynamicReshare(config, newParties, newThreshold, pl)
}