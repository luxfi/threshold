// Package keygen implements the LSS key generation protocol.
package keygen

import (
	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/lss/config"
)

// Start initiates the LSS key generation protocol.
func Start(selfID party.ID, participants []party.ID, threshold int, group curve.Curve, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		info := round.Info{
			ProtocolID:       "lss/keygen",
			FinalRoundNumber: 3,
			SelfID:           selfID,
			PartyIDs:         participants,
			Threshold:        threshold,
			Group:            group,
		}

		helper, err := round.NewSession(info, sessionID, pl)
		if err != nil {
			return nil, err
		}

		return &round1{
			Helper: helper,
		}, nil
	}
}

// Result contains the final output of the keygen protocol
type Result struct {
	Config *config.Config
}