package sign

import (
	"errors"

	"github.com/cronokirby/saferith"
	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/party"
)

// round2 collects nonces and generates partial signatures
type round2 struct {
	*round1

	// Collected nonces from all signers
	nonces map[party.ID]curve.Point

	// Combined nonce point R
	R curve.Point
}

// broadcast2 contains the partial signature
type broadcast2 struct {
	round.NormalBroadcastContent

	// Partial signature share
	PartialSig curve.Scalar
}

// Number implements round.Round
func (r *round2) Number() round.Number {
	return 2
}

// BroadcastContent implements round.BroadcastRound
func (r *round2) BroadcastContent() round.BroadcastContent {
	return &broadcast2{}
}

// MessageContent implements round.Round
func (r *round2) MessageContent() round.Content {
	return nil // No P2P messages
}

// RoundNumber implements round.Content
func (broadcast2) RoundNumber() round.Number {
	return 2
}

// VerifyMessage implements round.Round
func (r *round2) VerifyMessage(_ round.Message) error {
	return nil // No P2P messages
}

// StoreMessage implements round.Round
func (r *round2) StoreMessage(_ round.Message) error {
	return nil // No P2P messages
}

// Finalize implements round.Round
func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Add our own nonce
	r.nonces[r.SelfID()] = r.K

	// Verify we have nonces from all signers
	if len(r.nonces) != len(r.signers) {
		return nil, errors.New("missing nonces from some signers")
	}

	// Compute combined R = sum of all K values
	r.R = r.Group().NewPoint()
	for _, K := range r.nonces {
		r.R = r.R.Add(K)
	}

	// Convert R to scalar for signature
	// Get the X coordinate bytes
	rBytes, err := r.R.MarshalBinary()
	if err != nil {
		return nil, err
	}
	// Take first half as X coordinate (assuming compressed point format)
	halfLen := len(rBytes) / 2
	if halfLen > 32 {
		halfLen = 32
	}
	xBytes := rBytes[:halfLen]

	rScalar := r.Group().NewScalar()
	if err := rScalar.UnmarshalBinary(xBytes); err != nil {
		// If unmarshal fails, set directly from bytes with modular reduction
		rScalar.SetNat(new(saferith.Nat).SetBytes(xBytes))
	}

	// Convert message hash to scalar
	mScalar := r.Group().NewScalar()
	mScalar.SetNat(new(saferith.Nat).SetBytes(r.messageHash))

	// Compute Lagrange coefficient for our ID
	// This is simplified - in practice we need proper Lagrange interpolation
	lagrangeCoeff := polynomial.Lagrange(r.Group(), r.signers)[r.SelfID()]

	// Compute partial signature: s_i = k_i + r * λ_i * x_i * m
	// where λ_i is the Lagrange coefficient, x_i is our secret share
	partialSig := r.Group().NewScalar()
	partialSig = partialSig.Set(rScalar)        // r
	partialSig = partialSig.Mul(lagrangeCoeff)  // r * λ_i
	partialSig = partialSig.Mul(r.config.ECDSA) // r * λ_i * x_i
	partialSig = partialSig.Mul(mScalar)        // r * λ_i * x_i * m
	partialSig = partialSig.Add(r.k)            // k_i + r * λ_i * x_i * m

	// Broadcast partial signature
	if err := r.BroadcastMessage(out, &broadcast2{
		PartialSig: partialSig,
	}); err != nil {
		return nil, err
	}

	return &round3{
		round2:      r,
		partialSigs: make(map[party.ID]curve.Scalar),
		rScalar:     rScalar,
	}, nil
}

// StoreBroadcastMessage implements round.BroadcastRound
func (r *round2) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast1)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// Verify K is not identity
	if body.K == nil || body.K.IsIdentity() {
		return errors.New("invalid nonce commitment")
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

	r.nonces[from] = body.K
	return nil
}
