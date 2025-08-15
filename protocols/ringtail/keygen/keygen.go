package keygen

import (
	"errors"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/ringtail/config"
)

// Start initiates the Ringtail key generation protocol
func Start(selfID party.ID, participants []party.ID, threshold int, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		// Validate parameters
		if threshold < 1 || threshold > len(participants) {
			return nil, errors.New("invalid threshold")
		}

		info := round.Info{
			ProtocolID:       "ringtail/keygen",
			FinalRoundNumber: 3, // Ringtail keygen has 3 rounds
			SelfID:           selfID,
			PartyIDs:         participants,
			Threshold:        threshold,
		}

		helper, err := round.NewSession(info, sessionID, pl)
		if err != nil {
			return nil, err
		}

		// Default to 192-bit security
		cfg := config.NewConfig(selfID, threshold, config.Security192)

		// Start with round 1
		return &round1{
			Helper: helper,
			config: cfg,
			shares: make(map[party.ID][]byte),
		}, nil
	}
}
