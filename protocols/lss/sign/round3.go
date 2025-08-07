package sign

import (
	"errors"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
)

// round3 combines partial signatures
type round3 struct {
	*round2

	// Collected partial signatures
	partialSigs map[party.ID]curve.Scalar

	// r value from R point
	rScalar curve.Scalar
}

// Number implements round.Round
func (r *round3) Number() round.Number {
	return 3
}

// BroadcastContent implements round.BroadcastRound
func (r *round3) BroadcastContent() round.BroadcastContent {
	return nil // No broadcast in round 3
}

// MessageContent implements round.Round
func (r *round3) MessageContent() round.Content {
	return nil // No messages in round 3
}

// VerifyMessage implements round.Round
func (r *round3) VerifyMessage(_ round.Message) error {
	return nil // No messages to verify
}

// StoreMessage implements round.Round
func (r *round3) StoreMessage(_ round.Message) error {
	return nil // No messages to store
}

// Finalize implements round.Round
func (r *round3) Finalize(_ chan<- *round.Message) (round.Session, error) {
	// Verify we have partial signatures from all signers
	if len(r.partialSigs) != len(r.signers) {
		return nil, errors.New("missing partial signatures from some signers")
	}

	// Combine partial signatures: s = sum(s_i)
	s := r.Group().NewScalar()
	for _, partialSig := range r.partialSigs {
		s = s.Add(partialSig)
	}

	// Create final ECDSA signature
	sig := &ecdsa.Signature{
		R: r.R,
		S: s,
	}

	// Optionally verify the signature against the public key
	publicKey, err := r.config.PublicPoint()
	if err != nil {
		return nil, err
	}

	if !sig.Verify(publicKey, r.messageHash) {
		return nil, errors.New("signature verification failed")
	}

	return r.ResultRound(sig), nil
}

// StoreBroadcastMessage implements round.BroadcastRound
func (r *round3) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// Verify sender is a signer
	isSigner := false
	for _, id := range r.signers {
		if id == from {
			isSigner = true
			break
		}
	}
	if !isSigner {
		return errors.New("sender not in signers list")
	}

	// Store partial signature
	r.partialSigs[from] = body.PartialSig

	return nil
}
