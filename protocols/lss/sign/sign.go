// Package sign implements the LSS signing protocol.
package sign

import (
	"fmt"
	
	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/lss/config"
)

// Start initiates the LSS signing protocol.
func Start(c *config.Config, signers []party.ID, messageHash []byte, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		// Validate that all signers are known parties
		for _, signer := range signers {
			if _, ok := c.Public[signer]; !ok {
				return nil, fmt.Errorf("unknown signer: %s", signer)
			}
		}
		
		info := round.Info{
			ProtocolID:       "lss/sign",
			FinalRoundNumber: 3,
			SelfID:           c.ID,
			PartyIDs:         signers,
			Threshold:        c.Threshold,
			Group:            c.Group,
		}

		helper, err := round.NewSession(info, sessionID, pl)
		if err != nil {
			return nil, err
		}

		return &round1{
			Helper:      helper,
			config:      c,
			signers:     signers,
			messageHash: messageHash,
		}, nil
	}
}

// Result contains the final signature
type Result struct {
	Signature *ecdsa.Signature
}
