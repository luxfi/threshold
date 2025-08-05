// Package sign implements the LSS signing protocol.
package sign

import (
	"errors"
	"math/big"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/sample"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/lss"
)

// round1 generates nonces
type round1 struct {
	*round.Helper
	
	config      *lss.Config
	signers     []party.ID
	messageHash []byte
	
	// Local nonce
	k curve.Scalar
	K curve.Point
}

// StartSign initiates the signing protocol
func StartSign(info round.Info, pl *pool.Pool, config *lss.Config, messageHash []byte) (round.Session, error) {
	if len(info.PartyIDs) < config.Threshold {
		return nil, errors.New("not enough signers")
	}
	
	helper, err := round.NewSession(info, config.ID, info.PartyIDs, nil)
	if err != nil {
		return nil, err
	}
	
	// Generate random nonce
	k := sample.Scalar(pl, info.Group)
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

// VerifyMessage implements round.Round
func (r *round1) VerifyMessage(msg round.Message) error {
	// No messages in round 1
	return nil
}

// StoreMessage implements round.Round
func (r *round1) StoreMessage(msg round.Message) error {
	// No messages in round 1
	return nil
}

// Finalize implements round.Round
func (r *round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Broadcast nonce commitment
	commitment := &nonceCommitment{
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
	return &nonceCommitment{}
}

// Number implements round.Round
func (r *round1) Number() round.Number {
	return 1
}

// nonceCommitment is the nonce commitment message
type nonceCommitment struct {
	round.NormalBroadcastContent
	K curve.Point
}

// round2 collects nonces and generates partial signatures
type round2 struct {
	*round1
	nonces      map[party.ID]curve.Point
	lagrangeMap map[party.ID]curve.Scalar
}

// VerifyMessage implements round.Round
func (r *round2) VerifyMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*nonceCommitment)
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
	
	return nil
}

// StoreMessage implements round.Round
func (r *round2) StoreMessage(msg round.Message) error {
	from := msg.From
	body := msg.Content.(*nonceCommitment)
	r.nonces[from] = body.K
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
	rBytes := R.XBytes()
	rScalar := r.Group().NewScalar().SetBytes(rBytes)
	
	// Compute Lagrange coefficients for participating signers
	activeSigners := make([]party.ID, 0, len(r.nonces))
	for id := range r.nonces {
		activeSigners = append(activeSigners, id)
	}
	
	// For each signer i, compute Lagrange coefficient
	for _, i := range activeSigners {
		// Find index in original party list
		iIdx := -1
		for idx, id := range r.config.PartyIDs {
			if id == i {
				iIdx = idx + 1 // 1-indexed
				break
			}
		}
		if iIdx == -1 {
			return nil, errors.New("signer not in config")
		}
		
		lambda := r.Group().NewScalar().SetNat(1)
		for _, j := range activeSigners {
			if i == j {
				continue
			}
			
			// Find j's index
			jIdx := -1
			for idx, id := range r.config.PartyIDs {
				if id == j {
					jIdx = idx + 1 // 1-indexed
					break
				}
			}
			if jIdx == -1 {
				return nil, errors.New("signer not in config")
			}
			
			// lambda *= j / (j - i)
			num := r.Group().NewScalar().SetNat(uint(jIdx))
			den := r.Group().NewScalar().SetNat(uint(jIdx - iIdx))
			if jIdx < iIdx {
				// Handle negative denominator
				den = r.Group().NewScalar().Neg(r.Group().NewScalar().SetNat(uint(iIdx - jIdx)))
			}
			
			frac := r.Group().NewScalar().Mul(num, den.Invert())
			lambda = lambda.Mul(frac)
		}
		
		r.lagrangeMap[i] = lambda
	}
	
	// Compute partial signature: s_i = k_i + r * lambda_i * x_i * m
	m := r.Group().NewScalar().SetBytes(r.messageHash)
	si := r.Group().NewScalar()
	
	// si = ki + r * lambda_i * x_i * m
	lambda := r.lagrangeMap[r.SelfID()]
	si = r.Group().NewScalar().Mul(rScalar, lambda)
	si = si.Mul(r.config.SecretShare)
	si = si.Mul(m)
	si = si.Add(r.k)
	
	// Send partial signature
	partial := &partialSignature{
		si: si,
		R:  R,
	}
	
	if err := r.BroadcastMessage(out, partial); err != nil {
		return nil, err
	}
	
	return &round3{
		round2:     r,
		R:          R,
		partialSigs: make(map[party.ID]curve.Scalar),
	}, nil
}

// MessageContent implements round.Round
func (r *round2) MessageContent() round.Content {
	return &partialSignature{}
}

// Number implements round.Round
func (r *round2) Number() round.Number {
	return 2
}

// partialSignature contains a partial signature share
type partialSignature struct {
	round.NormalBroadcastContent
	si curve.Scalar
	R  curve.Point
}

// round3 combines partial signatures
type round3 struct {
	*round2
	R           curve.Point
	partialSigs map[party.ID]curve.Scalar
}

// VerifyMessage implements round.Round
func (r *round3) VerifyMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*partialSignature)
	if !ok {
		return round.ErrInvalidContent
	}
	
	// Verify R matches
	if !body.R.Equal(r.R) {
		return errors.New("R mismatch")
	}
	
	// Verify partial signature
	// g^si ?= Ki * Yi^(r * lambda_i * m)
	rBytes := r.R.XBytes()
	rScalar := r.Group().NewScalar().SetBytes(rBytes)
	m := r.Group().NewScalar().SetBytes(r.messageHash)
	
	// Get sender's public share
	Yi, ok := r.config.PublicShares[from]
	if !ok {
		return errors.New("missing public share for sender")
	}
	
	// Get sender's nonce commitment
	Ki, ok := r.nonces[from]
	if !ok {
		return errors.New("missing nonce for sender")
	}
	
	// Get Lagrange coefficient
	lambda, ok := r.lagrangeMap[from]
	if !ok {
		return errors.New("missing Lagrange coefficient")
	}
	
	// Compute expected = Ki * Yi^(r * lambda_i * m)
	exp := r.Group().NewScalar().Mul(rScalar, lambda)
	exp = exp.Mul(m)
	
	expected := Ki.Add(exp.Act(Yi))
	
	// Check g^si == expected
	actual := body.si.ActOnBase()
	if !actual.Equal(expected) {
		return errors.New("partial signature verification failed")
	}
	
	return nil
}

// StoreMessage implements round.Round
func (r *round3) StoreMessage(msg round.Message) error {
	from := msg.From
	body := msg.Content.(*partialSignature)
	r.partialSigs[from] = body.si
	return nil
}

// Finalize implements round.Round
func (r *round3) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Add own partial signature
	m := r.Group().NewScalar().SetBytes(r.messageHash)
	lambda := r.lagrangeMap[r.SelfID()]
	rBytes := r.R.XBytes()
	rScalar := r.Group().NewScalar().SetBytes(rBytes)
	
	si := r.Group().NewScalar().Mul(rScalar, lambda)
	si = si.Mul(r.config.SecretShare)
	si = si.Mul(m)
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
	
	// Create final signature
	rBig := new(big.Int).SetBytes(rBytes)
	sBig := new(big.Int).SetBytes(s.Bytes())
	
	sig := &ecdsa.Signature{
		R: rBig,
		S: sBig,
	}
	
	// Verify final signature
	if !sig.Verify(r.config.PublicKey, r.messageHash) {
		return nil, errors.New("final signature verification failed")
	}
	
	// Return result
	r.UpdateResult(protocol.Result(sig))
	return r.ResultRound(out), nil
}

// MessageContent implements round.Round
func (r *round3) MessageContent() round.Content {
	return nil
}

// Number implements round.Round
func (r *round3) Number() round.Number {
	return 3
}