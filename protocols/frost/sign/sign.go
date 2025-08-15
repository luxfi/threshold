package sign

import (
	"fmt"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/frost/keygen"
)

const (
	// Frost Sign with Threshold.
	protocolID        = "frost/sign-threshold"
	protocolIDTaproot = "frost/sign-threshold-taproot"
	// This protocol has 3 concrete rounds.
	protocolRounds round.Number = 3
)

func StartSignCommon(taproot bool, result *keygen.Config, signers []party.ID, messageHash []byte) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		// For FROST signing, we use the original threshold from keygen
		// The signers list should be at least threshold+1 parties
		// but we still use the original threshold for protocol validation
		signThreshold := result.Threshold

		// Validate we have enough signers - FROST requires exactly threshold (t) signers, not t+1
		if len(signers) < signThreshold {
			return nil, fmt.Errorf("insufficient signers: need at least %d, got %d", signThreshold, len(signers))
		}

		info := round.Info{
			FinalRoundNumber: protocolRounds,
			SelfID:           result.ID,
			PartyIDs:         signers,
			Threshold:        len(signers) - 1, // Session threshold is n-1 where n is number of participants
			Group:            result.PublicKey.Curve(),
		}
		if taproot {
			info.ProtocolID = protocolIDTaproot
		} else {
			info.ProtocolID = protocolID
		}

		helper, err := round.NewSession(info, sessionID, nil)
		if err != nil {
			return nil, fmt.Errorf("sign.StartSign: %w", err)
		}
		return &round1{
			Helper:  helper,
			taproot: taproot,
			M:       messageHash,
			Y:       result.PublicKey,
			YShares: result.VerificationShares.Points,
			sI:      result.PrivateShare,
		}, nil
	}
}
