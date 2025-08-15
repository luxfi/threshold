package sign

import (
	"errors"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/ringtail/config"
)

// Start initiates the Ringtail threshold signing protocol
func Start(cfg *config.Config, signers []party.ID, message []byte, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		// Validate we have enough signers
		if len(signers) < cfg.Threshold {
			return nil, errors.New("insufficient signers for threshold")
		}

		// Find our position in the signer list
		selfIdx := -1
		for i, id := range signers {
			if id == cfg.ID {
				selfIdx = i
				break
			}
		}
		if selfIdx == -1 {
			return nil, errors.New("self not in signer list")
		}

		info := round.Info{
			ProtocolID:       "ringtail/sign",
			FinalRoundNumber: 2, // Ringtail signing has 2 rounds
			SelfID:           cfg.ID,
			PartyIDs:         signers,
			Threshold:        cfg.Threshold,
		}

		helper, err := round.NewSession(info, sessionID, pl)
		if err != nil {
			return nil, err
		}

		// Start with signing round 1
		return &signRound1{
			Helper:  helper,
			config:  cfg,
			message: message,
			shares:  make(map[party.ID][]byte),
		}, nil
	}
}

// signRound1 generates and shares partial signatures
type signRound1 struct {
	*round.Helper
	config  *config.Config
	message []byte
	shares  map[party.ID][]byte
}

// Number implements round.Round
func (r *signRound1) Number() round.Number {
	return 1
}

// MessageContent implements round.Round
func (r *signRound1) MessageContent() round.Content {
	return nil // Signing uses broadcasts
}

// BroadcastContent implements round.BroadcastRound
func (r *signRound1) BroadcastContent() round.BroadcastContent {
	return &signBroadcast1{}
}

// VerifyMessage implements round.Round
func (r *signRound1) VerifyMessage(_ round.Message) error {
	return nil
}

// StoreMessage implements round.Round
func (r *signRound1) StoreMessage(_ round.Message) error {
	return nil
}

// StoreBroadcastMessage implements round.BroadcastRound
func (r *signRound1) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*signBroadcast1)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// Verify the partial signature from this party
	if !r.config.ValidateShare(msg.From, body.PartialSignature) {
		return errors.New("invalid partial signature")
	}

	r.shares[msg.From] = body.PartialSignature
	return nil
}

// Finalize implements round.Round
func (r *signRound1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Generate our partial signature using lattice operations
	// This is a placeholder - real implementation would use lattice crypto
	partialSig := make([]byte, 256) // Placeholder size
	copy(partialSig, r.config.PrivateShare[:min(256, len(r.config.PrivateShare))])

	// Broadcast our partial signature
	if err := r.BroadcastMessage(out, &signBroadcast1{
		PartialSignature: partialSig,
	}); err != nil {
		return nil, err
	}

	// Store our own share
	r.shares[r.SelfID()] = partialSig

	// Move to round 2 for aggregation
	return &signRound2{
		Helper:  r.Helper,
		config:  r.config,
		message: r.message,
		shares:  r.shares,
	}, nil
}

// signBroadcast1 contains a partial signature
type signBroadcast1 struct {
	round.NormalBroadcastContent
	PartialSignature []byte
}

// RoundNumber implements round.Content
func (signBroadcast1) RoundNumber() round.Number {
	return 1
}

// signRound2 aggregates partial signatures
type signRound2 struct {
	*round.Helper
	config  *config.Config
	message []byte
	shares  map[party.ID][]byte
}

// Number implements round.Round
func (r *signRound2) Number() round.Number {
	return 2
}

// MessageContent implements round.Round
func (r *signRound2) MessageContent() round.Content {
	return nil
}

// VerifyMessage implements round.Round
func (r *signRound2) VerifyMessage(_ round.Message) error {
	return nil
}

// StoreMessage implements round.Round
func (r *signRound2) StoreMessage(_ round.Message) error {
	return nil
}

// Finalize implements round.Round
func (r *signRound2) Finalize(_ chan<- *round.Message) (round.Session, error) {
	// Check we have enough shares
	if len(r.shares) < r.config.Threshold {
		return nil, errors.New("insufficient shares for threshold signature")
	}

	// Aggregate the lattice signatures
	// This is a placeholder - real implementation would use lattice aggregation
	finalSignature := make([]byte, 512)
	offset := 0
	for _, share := range r.shares {
		if offset+len(share) <= len(finalSignature) {
			copy(finalSignature[offset:], share)
			offset += len(share)
		}
		if offset >= r.config.Threshold*64 {
			break // We have enough
		}
	}

	// Return the final signature
	return r.ResultRound(&RingtailSignature{
		Signature: finalSignature,
		Message:   r.message,
		Signers:   r.PartyIDs(),
	}), nil
}

// RingtailSignature represents a completed threshold signature
type RingtailSignature struct {
	Signature []byte
	Message   []byte
	Signers   []party.ID
}

// Verify checks if the signature is valid
func (s *RingtailSignature) Verify(publicKey []byte) bool {
	return config.VerifySignature(publicKey, s.Message, s.Signature)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
