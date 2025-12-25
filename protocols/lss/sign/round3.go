package sign

import (
	"errors"

	"github.com/cronokirby/saferith"
	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
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
	// Add our own partial signature (computed in round2.Finalize but we need to include it)
	// We need to recompute it since we didn't store it
	lagrangeCoeff := polynomial.Lagrange(r.Group(), r.signers)[r.SelfID()]

	// Recompute our partial sig: s_i = k_i + r * λ_i * x_i * m
	ourPartialSig := r.Group().NewScalar()
	ourPartialSig = ourPartialSig.Set(r.rScalar)        // r
	ourPartialSig = ourPartialSig.Mul(lagrangeCoeff)    // r * λ_i
	ourPartialSig = ourPartialSig.Mul(r.config.ECDSA)   // r * λ_i * x_i

	// Convert message hash to scalar
	mScalar := r.Group().NewScalar()
	mScalar.SetNat(new(saferith.Nat).SetBytes(r.messageHash))
	ourPartialSig = ourPartialSig.Mul(mScalar) // r * λ_i * x_i * m
	ourPartialSig = ourPartialSig.Add(r.k)     // k_i + r * λ_i * x_i * m

	// Add our own partial sig
	r.partialSigs[r.SelfID()] = ourPartialSig

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

// StoreBroadcastMessage implements round.BroadcastRound - no-op for round3
func (r *round3) StoreBroadcastMessage(_ round.Message) error {
	return nil // Round3 doesn't receive broadcasts - partial sigs passed from round2
}
