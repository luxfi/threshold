package sign

import (
	"crypto/rand"
	"errors"
	"sync"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/sample"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/lss/config"
)

// round1 generates nonces for signing
type round1 struct {
	*round.Helper

	config      *config.Config
	signers     []party.ID
	messageHash []byte

	// Our nonce pair
	k curve.Scalar // Secret nonce
	K curve.Point  // Public nonce commitment g^k

	// Storage for received nonces from other parties
	receivedNonces sync.Map // map[party.ID]curve.Point
}

// broadcast1 contains the nonce commitment
type broadcast1 struct {
	round.NormalBroadcastContent

	// Public nonce commitment - stored as bytes for CBOR compatibility
	K []byte
}

// Number implements round.Round
func (r *round1) Number() round.Number {
	return 1
}

// BroadcastContent implements round.BroadcastRound
func (r *round1) BroadcastContent() round.BroadcastContent {
	return &broadcast1{}
}

// MessageContent implements round.Round
func (r *round1) MessageContent() round.Content {
	return nil // No P2P messages in round 1
}

// RoundNumber implements round.Content
func (broadcast1) RoundNumber() round.Number {
	return 1
}

// VerifyMessage implements round.Round
func (r *round1) VerifyMessage(_ round.Message) error {
	return nil // No P2P messages
}

// StoreMessage implements round.Round
func (r *round1) StoreMessage(_ round.Message) error {
	return nil // No P2P messages
}

// Finalize implements round.Round
func (r *round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Generate random nonce
	r.k = sample.Scalar(rand.Reader, r.Group())
	r.K = r.k.ActOnBase()

	// Marshal K to bytes for broadcast
	kBytes, err := r.K.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// Broadcast nonce commitment
	if err := r.BroadcastMessage(out, &broadcast1{
		K: kBytes,
	}); err != nil {
		return nil, err
	}

	// Collect received nonces from sync.Map
	nonces := make(map[party.ID]curve.Point)
	r.receivedNonces.Range(func(key, value interface{}) bool {
		id := key.(party.ID)
		nonces[id] = value.(curve.Point)
		return true
	})

	return &round2{
		round1: r,
		nonces: nonces,
	}, nil
}

// StoreBroadcastMessage implements round.BroadcastRound
func (r *round1) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*broadcast1)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// Unmarshal K from bytes
	K, err := body.GetK(r.Group())
	if err != nil {
		return errors.New("invalid nonce commitment: " + err.Error())
	}

	// Verify K is not identity
	if K.IsIdentity() {
		return errors.New("invalid nonce commitment: identity point")
	}

	// Verify sender is a signer
	isSigner := false
	for _, id := range r.signers {
		if id == msg.From {
			isSigner = true
			break
		}
	}
	if !isSigner {
		return errors.New("sender not in signers list")
	}

	// Store using sync.Map for thread safety
	r.receivedNonces.Store(msg.From, K)
	return nil
}

// GetK unmarshals the K bytes into a curve.Point
func (b *broadcast1) GetK(group curve.Curve) (curve.Point, error) {
	if len(b.K) == 0 {
		return nil, errors.New("missing nonce commitment")
	}
	point := group.NewPoint()
	if err := point.UnmarshalBinary(b.K); err != nil {
		return nil, err
	}
	return point, nil
}
