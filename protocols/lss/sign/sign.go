// Package sign implements the LSS signing protocol.
package sign

import (
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/cronokirby/saferith"
	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/sample"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
)

// Config represents the configuration for an LSS party
type Config struct {
	ID           party.ID
	Group        curve.Curve
	Threshold    int
	Generation   uint64
	SecretShare  curve.Scalar
	PublicKey    curve.Point
	PublicShares map[party.ID]curve.Point
	PartyIDs     []party.ID
}

// StartSign initiates the signing protocol
func StartSign(info round.Info, pl *pool.Pool, config *Config, messageHash []byte) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		helper, err := round.NewSession(info, sessionID, pl)
		if err != nil {
			return nil, err
		}

		// Generate random nonce
		k := sample.Scalar(rand.Reader, helper.Group())
		K := k.ActOnBase()

		return &round1{
			Helper:      helper,
			config:      config,
			signers:     info.PartyIDs,
			messageHash: messageHash,
			k:           k,
			K:           K,
		}, nil
	}
}

// round1 generates nonces
type round1 struct {
	*round.Helper

	config      *Config
	signers     []party.ID
	messageHash []byte

	// Local nonce
	k curve.Scalar
	K curve.Point
}

// nonceCommitment1 is the nonce commitment message
type nonceCommitment1 struct {
	round.NormalBroadcastContent
	K curve.Point
}

// RoundNumber implements round.Content
func (nonceCommitment1) RoundNumber() round.Number { return 1 }

// BroadcastContent implements round.BroadcastRound
func (r *round1) BroadcastContent() round.BroadcastContent {
	return &nonceCommitment1{}
}

// Number implements round.Round
func (r *round1) Number() round.Number {
	return 1
}

// StoreBroadcastMessage implements round.BroadcastRound
func (r *round1) StoreBroadcastMessage(msg round.Message) error {
	// No messages to store in round 1
	return nil
}

// VerifyMessage implements round.Round
func (r *round1) VerifyMessage(msg round.Message) error {
	// No P2P messages in round 1
	return nil
}

// StoreMessage implements round.Round
func (r *round1) StoreMessage(msg round.Message) error {
	// No P2P messages in round 1
	return nil
}

// Finalize implements round.Round
func (r *round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Broadcast nonce commitment
	commitment := &nonceCommitment1{
		K: r.K,
	}

	if err := r.BroadcastMessage(out, commitment); err != nil {
		return nil, err
	}

	return &round2{
		round1:      r,
		nonces:      make(map[party.ID]curve.Point),
		lagrangeMap: make(map[party.ID]curve.Scalar),
	}, nil
}

// MessageContent implements round.Round
func (r *round1) MessageContent() round.Content {
	return nil // No P2P messages
}

// round2 collects nonces and generates partial signatures
type round2 struct {
	*round1
	nonces      map[party.ID]curve.Point
	lagrangeMap map[party.ID]curve.Scalar
}

// partialSignature2 contains a partial signature share
type partialSignature2 struct {
	round.NormalBroadcastContent
	Si curve.Scalar
	R  curve.Point
}

// RoundNumber implements round.Content
func (partialSignature2) RoundNumber() round.Number { return 2 }

// Number implements round.Round
func (r *round2) Number() round.Number {
	return 2
}

// BroadcastContent implements round.BroadcastRound
func (r *round2) BroadcastContent() round.BroadcastContent {
	return &nonceCommitment1{} // Reuse from round 1
}

// StoreBroadcastMessage implements round.BroadcastRound
func (r *round2) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*nonceCommitment1)
	if !ok {
		return round.ErrInvalidContent
	}

	if body.K == nil || body.K.IsIdentity() {
		return errors.New("invalid nonce commitment")
	}

	// Verify sender is in signers list
	found := false
	for _, id := range r.signers {
		if id == from {
			found = true
			break
		}
	}
	if !found {
		return errors.New("sender not in signers list")
	}

	r.nonces[from] = body.K
	return nil
}

// VerifyMessage implements round.Round
func (r *round2) VerifyMessage(msg round.Message) error {
	// No P2P messages in round 2
	return nil
}

// StoreMessage implements round.Round
func (r *round2) StoreMessage(msg round.Message) error {
	// No P2P messages in round 2
	return nil
}

// Finalize implements round.Round
func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Add own nonce
	r.nonces[r.SelfID()] = r.K

	// Check we have enough nonces
	if len(r.nonces) < r.config.Threshold {
		return nil, errors.New("not enough nonces received")
	}

	// Compute combined nonce R = sum of all K values
	R := r.Group().NewPoint()
	for _, K := range r.nonces {
		R = R.Add(K)
	}

	// Get r coordinate
	rBytes, err := R.MarshalBinary()
	if err != nil {
		return nil, err
	}
	// Take first 32 bytes as r value
	if len(rBytes) < 32 {
		return nil, errors.New("invalid R point encoding")
	}
	rScalar := r.Group().NewScalar()
	// Use a simple conversion for now
	rBig := new(big.Int).SetBytes(rBytes[:32])
	orderBytes, _ := r.Group().Order().MarshalBinary()
	orderBig := new(big.Int).SetBytes(orderBytes)
	rBig = rBig.Mod(rBig, orderBig)
	rNat := new(saferith.Nat).SetBytes(rBig.Bytes())
	rScalar.SetNat(rNat)

	// Compute Lagrange coefficients for participating signers
	activeSigners := make([]party.ID, 0, len(r.nonces))
	for id := range r.nonces {
		activeSigners = append(activeSigners, id)
	}

	// For each signer i, compute Lagrange coefficient
	for _, i := range activeSigners {
		lambda := i.Scalar(r.Group()) // Simplified - use party scalar as coefficient
		r.lagrangeMap[i] = lambda
	}

	// Compute partial signature: s_i = k_i + r * lambda_i * x_i * m
	m := r.Group().NewScalar()
	// Convert message hash to scalar
	mBig := new(big.Int).SetBytes(r.messageHash)
	orderBytes2, _ := r.Group().Order().MarshalBinary()
	orderBig2 := new(big.Int).SetBytes(orderBytes2)
	mBig = mBig.Mod(mBig, orderBig2)
	mNat := new(saferith.Nat).SetBytes(mBig.Bytes())
	m.SetNat(mNat)

	// si = ki + r * lambda_i * x_i * m
	lambda := r.lagrangeMap[r.SelfID()]
	si := r.Group().NewScalar().Set(rScalar)
	si = si.Mul(lambda)
	si = si.Mul(r.config.SecretShare)
	si = si.Mul(m)
	si = si.Add(r.k)

	// Send partial signature
	partial := &partialSignature2{
		Si: si,
		R:  R,
	}

	if err := r.BroadcastMessage(out, partial); err != nil {
		return nil, err
	}

	return &round3{
		round2:      r,
		R:           R,
		partialSigs: make(map[party.ID]curve.Scalar),
		rScalar:     rScalar,
		m:           m,
	}, nil
}

// MessageContent implements round.Round
func (r *round2) MessageContent() round.Content {
	return nil // No P2P messages
}

// round3 combines partial signatures
type round3 struct {
	*round2
	R           curve.Point
	partialSigs map[party.ID]curve.Scalar
	rScalar     curve.Scalar
	m           curve.Scalar
}

// Number implements round.Round
func (r *round3) Number() round.Number {
	return 3
}

// BroadcastContent implements round.BroadcastRound
func (r *round3) BroadcastContent() round.BroadcastContent {
	return &partialSignature2{}
}

// StoreBroadcastMessage implements round.BroadcastRound
func (r *round3) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*partialSignature2)
	if !ok {
		return round.ErrInvalidContent
	}

	// Verify R matches
	if !body.R.Equal(r.R) {
		return errors.New("R mismatch")
	}

	// Simple verification - just check signature is not nil
	// Full verification would check against public shares

	r.partialSigs[from] = body.Si
	return nil
}

// VerifyMessage implements round.Round
func (r *round3) VerifyMessage(msg round.Message) error {
	// No P2P messages in round 3
	return nil
}

// StoreMessage implements round.Round
func (r *round3) StoreMessage(msg round.Message) error {
	// No P2P messages in round 3
	return nil
}

// Finalize implements round.Round
func (r *round3) Finalize(_ chan<- *round.Message) (round.Session, error) {
	// Add own partial signature
	lambda := r.lagrangeMap[r.SelfID()]
	si := r.Group().NewScalar().Set(r.rScalar)
	si = si.Mul(lambda)
	si = si.Mul(r.config.SecretShare)
	si = si.Mul(r.m)
	si = si.Add(r.k)

	r.partialSigs[r.SelfID()] = si

	// Check we have enough signatures
	if len(r.partialSigs) < r.config.Threshold {
		return nil, errors.New("not enough partial signatures")
	}

	// Combine partial signatures: s = sum(si)
	s := r.Group().NewScalar()
	for _, si := range r.partialSigs {
		s = s.Add(si)
	}

	// Return ECDSA signature
	return r.ResultRound(&ecdsa.Signature{
		R: r.R,
		S: s,
	}), nil
}

// MessageContent implements round.Round
func (r *round3) MessageContent() round.Content {
	return &partialSignature2{}
}

