// Package keygen implements distributed key generation for Ringtail threshold signatures.
// This package wraps the real Ringtail implementation from github.com/luxfi/ringtail.
package keygen

import (
	"errors"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/ringtail/config"

	realring "github.com/luxfi/corona/threshold"
)

// Start initiates the Ringtail key generation protocol.
// This wraps the real Ringtail keygen from github.com/luxfi/ringtail/threshold.
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

		// Default to 128-bit security (uses real ringtail params)
		cfg := config.NewConfig(selfID, threshold, config.Security128)

		// Find our index in the participant list
		selfIndex := -1
		for i, id := range participants {
			if id == selfID {
				selfIndex = i
				break
			}
		}
		if selfIndex == -1 {
			return nil, errors.New("self not in participant list")
		}

		// Start with round 1
		return &round1{
			Helper:       helper,
			config:       cfg,
			shares:       make(map[party.ID][]byte),
			selfIndex:    selfIndex,
			participants: participants,
		}, nil
	}
}

// KeygenOutput represents the result of key generation.
// It wraps the real ringtail KeyShare.
type KeygenOutput struct {
	Config   *config.Config
	KeyShare *realring.KeyShare
	GroupKey *realring.GroupKey
}

// PublicKey returns the generated public key
func (o *KeygenOutput) PublicKey() []byte {
	if o.GroupKey != nil {
		return o.GroupKey.Bytes()
	}
	return o.Config.PublicKey
}

// PrivateShare returns this party's private key share
func (o *KeygenOutput) PrivateShare() []byte {
	return o.Config.PrivateShare
}

// GetKeyShare returns the real ringtail KeyShare for use in signing
func (o *KeygenOutput) GetKeyShare() *realring.KeyShare {
	return o.KeyShare
}

// GetGroupKey returns the real ringtail GroupKey for use in signing
func (o *KeygenOutput) GetGroupKey() *realring.GroupKey {
	return o.GroupKey
}
