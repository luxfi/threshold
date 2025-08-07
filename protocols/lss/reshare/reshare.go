// Package reshare implements the LSS dynamic resharing protocol.
package reshare

import (
	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/lss/config"
)

// Start initiates the LSS resharing protocol.
func Start(oldConfig *config.Config, newParticipants []party.ID, newThreshold int, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		// Determine if we're in the old group, new group, or both
		oldID := oldConfig.ID
		inOldGroup := false
		inNewGroup := false

		for _, id := range oldConfig.PartyIDs() {
			if id == oldID {
				inOldGroup = true
				break
			}
		}

		for _, id := range newParticipants {
			if id == oldID {
				inNewGroup = true
				break
			}
		}

		// Combine old and new participants for the protocol
		allParticipants := make(map[party.ID]bool)
		for _, id := range oldConfig.PartyIDs() {
			allParticipants[id] = true
		}
		for _, id := range newParticipants {
			allParticipants[id] = true
		}

		participantList := make([]party.ID, 0, len(allParticipants))
		for id := range allParticipants {
			participantList = append(participantList, id)
		}

		info := round.Info{
			ProtocolID:       "lss/reshare",
			FinalRoundNumber: 3,
			SelfID:           oldID,
			PartyIDs:         participantList,
			Threshold:        newThreshold,
			Group:            oldConfig.Group,
		}

		helper, err := round.NewSession(info, sessionID, pl)
		if err != nil {
			return nil, err
		}

		return &round1{
			Helper:          helper,
			oldConfig:       oldConfig,
			newParticipants: newParticipants,
			newThreshold:    newThreshold,
			inOldGroup:      inOldGroup,
			inNewGroup:      inNewGroup,
		}, nil
	}
}

// Result contains the final output of the reshare protocol
type Result struct {
	Config *config.Config
}
