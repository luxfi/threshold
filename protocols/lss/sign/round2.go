package sign

import (
	"errors"
	"sync"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/party"
)

// round2 collects nonces and generates partial signatures
type round2 struct {
	*round1

	// Collected nonces from all signers (passed from round1)
	nonces map[party.ID]curve.Point

	// Combined nonce point R
	R curve.Point

	// Storage for received partial sigs from other parties
	receivedPartialSigs sync.Map // map[party.ID]curve.Scalar
}

// broadcast2 contains the partial signature
type broadcast2 struct {
	round.NormalBroadcastContent

	// Partial signature share - stored as bytes for CBOR compatibility
	PartialSig []byte
}

// GetPartialSig unmarshals the PartialSig bytes into a curve.Scalar
func (b *broadcast2) GetPartialSig(group curve.Curve) (curve.Scalar, error) {
	if len(b.PartialSig) == 0 {
		return nil, errors.New("missing partial signature")
	}
	scalar := group.NewScalar()
	if err := scalar.UnmarshalBinary(b.PartialSig); err != nil {
		return nil, err
	}
	return scalar, nil
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
	// Collect nonces fresh from round1's sync.Map
	// This is necessary because round2 may have been created before all broadcasts
	// were received (during initializeRound), so the nonces map may be stale
	r.round1.receivedNonces.Range(func(key, value interface{}) bool {
		id := key.(party.ID)
		r.nonces[id] = value.(curve.Point)
		return true
	})

	// Add our own nonce
	r.nonces[r.SelfID()] = r.K

	// Verify we have nonces from all signers
	if len(r.nonces) != len(r.signers) {
		return nil, errors.New("missing nonces from some signers")
	}

	// Compute combined R = sum of all K values (nonce commitment)
	r.R = r.Group().NewPoint()
	for _, K := range r.nonces {
		r.R = r.R.Add(K)
	}

	// Get public key for challenge computation
	publicKey, err := r.config.PublicPoint()
	if err != nil {
		return nil, err
	}

	// Compute Schnorr challenge: c = H(R || Y || m)
	// Using curve.FromHash for proper domain separation
	rBytes, err := r.R.MarshalBinary()
	if err != nil {
		return nil, err
	}
	yBytes, err := publicKey.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// Concatenate R || Y || m for challenge hash
	challengeInput := make([]byte, 0, len(rBytes)+len(yBytes)+len(r.messageHash))
	challengeInput = append(challengeInput, rBytes...)
	challengeInput = append(challengeInput, yBytes...)
	challengeInput = append(challengeInput, r.messageHash...)
	challenge := curve.FromHash(r.Group(), challengeInput)

	// Compute Lagrange coefficient for our ID
	lagrangeCoeff := polynomial.Lagrange(r.Group(), r.signers)[r.SelfID()]

	// Compute partial Schnorr signature: z_i = k_i + c * λ_i * x_i
	// where c is the challenge, λ_i is the Lagrange coefficient, x_i is our secret share
	// When aggregated: z = sum(z_i) = sum(k_i) + c * sum(λ_i * x_i) = k + c * x
	partialSig := r.Group().NewScalar()
	partialSig = partialSig.Set(challenge)      // c
	partialSig = partialSig.Mul(lagrangeCoeff)  // c * λ_i
	partialSig = partialSig.Mul(r.config.ECDSA) // c * λ_i * x_i
	partialSig = partialSig.Add(r.k)            // k_i + c * λ_i * x_i

	// Marshal partial signature to bytes for broadcast
	partialSigBytes, err := partialSig.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// Broadcast partial signature
	if err := r.BroadcastMessage(out, &broadcast2{
		PartialSig: partialSigBytes,
	}); err != nil {
		return nil, err
	}

	// Store our own partial sig so round3 can collect it
	r.receivedPartialSigs.Store(r.SelfID(), partialSig)

	// Collect received partial sigs from sync.Map
	partialSigs := make(map[party.ID]curve.Scalar)
	r.receivedPartialSigs.Range(func(key, value interface{}) bool {
		id := key.(party.ID)
		partialSigs[id] = value.(curve.Scalar)
		return true
	})

	return &round3{
		round2:      r,
		partialSigs: partialSigs,
		challenge:   challenge,
	}, nil
}

// StoreBroadcastMessage implements round.BroadcastRound
func (r *round2) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// Unmarshal partial sig from bytes
	partialSig, err := body.GetPartialSig(r.Group())
	if err != nil {
		return errors.New("invalid partial signature: " + err.Error())
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

	// Store using sync.Map for thread safety
	r.receivedPartialSigs.Store(from, partialSig)
	return nil
}
