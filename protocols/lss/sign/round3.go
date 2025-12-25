package sign

import (
	"errors"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
)

// round3 combines partial signatures and verifies the final Schnorr signature
type round3 struct {
	*round2

	// Collected partial signatures
	partialSigs map[party.ID]curve.Scalar

	// Schnorr challenge c = H(R || Y || m)
	challenge curve.Scalar
}

// SchnorrSignature represents a threshold Schnorr signature
type SchnorrSignature struct {
	R curve.Point  // Combined nonce point
	Z curve.Scalar // Combined signature scalar
}

// Verify verifies a Schnorr signature: z*G == R + c*Y
func (sig *SchnorrSignature) Verify(publicKey curve.Point, messageHash []byte) bool {
	if sig.R == nil || sig.Z == nil || publicKey == nil {
		return false
	}

	group := sig.R.Curve()

	// Recompute challenge: c = H(R || Y || m)
	rBytes, err := sig.R.MarshalBinary()
	if err != nil {
		return false
	}
	yBytes, err := publicKey.MarshalBinary()
	if err != nil {
		return false
	}

	challengeInput := make([]byte, 0, len(rBytes)+len(yBytes)+len(messageHash))
	challengeInput = append(challengeInput, rBytes...)
	challengeInput = append(challengeInput, yBytes...)
	challengeInput = append(challengeInput, messageHash...)
	challenge := curve.FromHash(group, challengeInput)

	// Verify: z*G == R + c*Y
	// Left side: z*G
	left := sig.Z.ActOnBase()

	// Right side: R + c*Y
	cY := challenge.Act(publicKey)
	right := sig.R.Add(cY)

	return left.Equal(right)
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
	// Collect partial sigs fresh from round2's sync.Map
	// This is necessary because round3 may have been created before all broadcasts
	// were received (during initializeRound), so the partialSigs map may be stale
	r.round2.receivedPartialSigs.Range(func(key, value interface{}) bool {
		id := key.(party.ID)
		r.partialSigs[id] = value.(curve.Scalar)
		return true
	})

	// Verify we have partial signatures from all signers
	// Our own partial sig is already stored in round2.receivedPartialSigs
	if len(r.partialSigs) != len(r.signers) {
		return nil, errors.New("missing partial signatures from some signers")
	}

	// Combine partial signatures: z = sum(z_i)
	z := r.Group().NewScalar()
	for _, partialSig := range r.partialSigs {
		z = z.Add(partialSig)
	}

	// Create final Schnorr signature
	sig := &SchnorrSignature{
		R: r.R,
		Z: z,
	}

	// Verify the signature against the public key
	publicKey, err := r.config.PublicPoint()
	if err != nil {
		return nil, err
	}

	if !sig.Verify(publicKey, r.messageHash) {
		return nil, errors.New("signature verification failed")
	}

	return r.ResultRound(sig), nil
}

// StoreBroadcastMessage implements round.BroadcastRound - no-op for round3
func (r *round3) StoreBroadcastMessage(_ round.Message) error {
	return nil // Round3 doesn't receive broadcasts - partial sigs passed from round2
}
