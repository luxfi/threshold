package sign

import (
	"fmt"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/frost/keygen"
)

const (
	// Frost Sign with Threshold.
	protocolID        = "frost/sign-threshold"
	protocolIDTaproot = "frost/sign-threshold-taproot"
	protocolIDSR25519 = "frost/sign-threshold-sr25519"
	protocolIDEd25519 = "frost/sign-threshold-ed25519"
	// This protocol has 3 concrete rounds.
	protocolRounds round.Number = 3
)

func StartSignCommon(taproot bool, result *keygen.Config, signers []party.ID, messageHash []byte) protocol.StartFunc {
	return startSign(taproot, false, false, nil, result, signers, messageHash)
}

func StartSignSR25519Common(taproot, sr25519 bool, signingContext []byte, result *keygen.Config, signers []party.ID, messageHash []byte) protocol.StartFunc {
	return startSign(taproot, sr25519, false, signingContext, result, signers, messageHash)
}

// StartSignEd25519Common produces an RFC 8032 PureEdDSA signature.
//
// result must come from a key generation over curve.Ed25519, and message is the
// raw message: PureEdDSA signs M itself, so callers must not pre-hash it.
func StartSignEd25519Common(result *keygen.Config, signers []party.ID, message []byte) protocol.StartFunc {
	return startSign(false, false, true, nil, result, signers, message)
}

func startSign(taproot, sr25519, ed25519 bool, signingContext []byte, result *keygen.Config, signers []party.ID, messageHash []byte) protocol.StartFunc {
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
		if sr25519 {
			info.ProtocolID = protocolIDSR25519
		} else if ed25519 {
			if _, ok := result.PublicKey.Curve().(curve.Ed25519); !ok {
				return nil, fmt.Errorf("sign.StartSign: ed25519 signing requires an ed25519 key, got %q", result.PublicKey.Curve().Name())
			}
			info.ProtocolID = protocolIDEd25519
		} else if taproot {
			info.ProtocolID = protocolIDTaproot
		} else {
			info.ProtocolID = protocolID
		}

		helper, err := round.NewSession(info, sessionID, nil)
		if err != nil {
			return nil, fmt.Errorf("sign.StartSign: %w", err)
		}
		return &round1{
			Base:           helper,
			taproot:        taproot,
			sr25519:        sr25519,
			ed25519:        ed25519,
			signingContext: signingContext,
			M:              messageHash,
			Y:              result.PublicKey,
			YShares:        result.VerificationShares.Points,
			sI:             result.PrivateShare,
		}, nil
	}
}
