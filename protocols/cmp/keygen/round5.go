package keygen

import (
	"errors"

	"github.com/luxfi/threshold/internal/round"
	sch "github.com/luxfi/threshold/pkg/zk/sch"
	"github.com/luxfi/threshold/protocols/cmp/config"
)

var _ round.Round = (*round5)(nil)

type round5 struct {
	*round4
	UpdatedConfig *config.Config
}

type broadcast5 struct {
	round.NormalBroadcastContent
	// SchnorrResponse is the Schnorr proof of knowledge of the new secret share
	SchnorrResponse *sch.Response
}

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - verify all Schnorr proof for the new ecdsa share.
func (r *round5) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast5)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if !body.SchnorrResponse.IsValid() {
		return round.ErrNilFields
	}

	// Load Schnorr commitment from sync.Map
	schnorrCommitValue, ok := r.SchnorrCommitments.Load(from)
	if !ok {
		return errors.New("schnorr commitment not found for party")
	}
	schnorrCommit, ok := schnorrCommitValue.(*sch.Commitment)
	if !ok || schnorrCommit == nil {
		return errors.New("invalid schnorr commitment for party")
	}

	// Check if public key exists for party
	if r.UpdatedConfig == nil || r.UpdatedConfig.Public == nil {
		return errors.New("updated config not initialized")
	}
	if _, ok := r.UpdatedConfig.Public[from]; !ok {
		return errors.New("public key not found in updated config for party")
	}

	if !body.SchnorrResponse.Verify(r.HashForID(from),
		r.UpdatedConfig.Public[from].ECDSA,
		schnorrCommit, nil) {
		return errors.New("failed to validate schnorr proof for received share")
	}
	return nil
}

// VerifyMessage implements round.Round.
func (round5) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (r *round5) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round.
func (r *round5) Finalize(chan<- *round.Message) (round.Session, error) {
	return r.ResultRound(r.UpdatedConfig), nil
}

// MessageContent implements round.Round.
func (r *round5) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcast5) RoundNumber() round.Number { return 5 }

// BroadcastContent implements round.BroadcastRound.
func (r *round5) BroadcastContent() round.BroadcastContent {
	return &broadcast5{
		SchnorrResponse: sch.EmptyResponse(r.Group()),
	}
}

// Number implements round.Round.
func (round5) Number() round.Number { return 5 }
