package thresholdd

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"

	luxbls "github.com/luxfi/crypto/bls"
	"github.com/luxfi/threshold/pkg/party"
	tbls "github.com/luxfi/threshold/protocols/bls"
)

// blsScheme wires luxfi/threshold/protocols/bls (Shamir t-of-n with
// Lagrange interpolation over BLS12-381 G2 signatures) into the
// dispatcher's scheme surface. Keygen runs a TrustedDealer in-process
// — that is the canonical luxfi/threshold path (see protocols/bls/bls_test.go).
type blsScheme struct {
	mu       sync.Mutex
	sessions map[string]*blsSession
}

type blsSession struct {
	threshold int
	configs   map[party.ID]*tbls.Config
	partyIDs  []party.ID
}

func newBLSScheme() *blsScheme {
	return &blsScheme{sessions: make(map[string]*blsSession)}
}

func (s *blsScheme) Keygen(p keygenParams) (keygenResult, error) {
	if err := validateKeygenParams(p); err != nil {
		return keygenResult{}, err
	}
	ids := partyIDs(p.Participants)
	dealer := &tbls.TrustedDealer{
		Threshold:    p.Threshold,
		TotalParties: p.Participants,
	}
	shares, groupPK, err := dealer.GenerateShares(context.Background(), ids)
	if err != nil {
		return keygenResult{}, fmt.Errorf("bls keygen: %w", err)
	}
	vks := tbls.GetVerificationKeys(shares)

	configs := make(map[party.ID]*tbls.Config, len(ids))
	for _, id := range ids {
		configs[id] = tbls.NewConfig(id, p.Threshold, p.Participants, shares[id], groupPK, vks)
	}

	pkBytes := luxbls.PublicKeyToCompressedBytes(groupPK)
	pkHex := hex.EncodeToString(pkBytes)

	shareHex := make([]string, 0, len(ids))
	for _, id := range ids {
		shareHex = append(shareHex, hex.EncodeToString(luxbls.SecretKeyToBytes(shares[id])))
	}

	s.mu.Lock()
	s.sessions[pkHex] = &blsSession{
		threshold: p.Threshold,
		configs:   configs,
		partyIDs:  ids,
	}
	s.mu.Unlock()

	return keygenResult{PublicKey: pkHex, Shares: shareHex}, nil
}

func (s *blsScheme) Sign(p signParams) (signResult, error) {
	msg, err := hex.DecodeString(p.MessageHex)
	if err != nil {
		return signResult{}, fmt.Errorf("messageHex: %w", err)
	}
	s.mu.Lock()
	sess, ok := s.sessions[p.PubKeyHex]
	s.mu.Unlock()
	if !ok {
		return signResult{}, fmt.Errorf("bls sign: unknown pubKeyHex (keygen first)")
	}

	signers := sess.partyIDs[:sess.threshold]
	parts := make([]*tbls.SignatureShare, 0, len(signers))
	for _, id := range signers {
		share, err := sess.configs[id].Sign(msg)
		if err != nil {
			return signResult{}, fmt.Errorf("party %s sign: %w", id, err)
		}
		parts = append(parts, share)
	}
	sig, err := tbls.AggregateSignatures(parts, sess.threshold)
	if err != nil {
		return signResult{}, fmt.Errorf("aggregate: %w", err)
	}
	sigBytes := luxbls.SignatureToBytes(sig)
	return signResult{SignatureHex: hex.EncodeToString(sigBytes)}, nil
}

func (s *blsScheme) Verify(p verifyParams) (verifyResult, error) {
	msg, err := hex.DecodeString(p.MessageHex)
	if err != nil {
		return verifyResult{}, fmt.Errorf("messageHex: %w", err)
	}
	sigBytes, err := hex.DecodeString(p.SignatureHex)
	if err != nil {
		return verifyResult{}, fmt.Errorf("signatureHex: %w", err)
	}
	pkBytes, err := hex.DecodeString(p.PubKeyHex)
	if err != nil {
		return verifyResult{}, fmt.Errorf("pubKeyHex: %w", err)
	}
	pk, err := luxbls.PublicKeyFromCompressedBytes(pkBytes)
	if err != nil {
		return verifyResult{OK: false}, nil
	}
	sig, err := luxbls.SignatureFromBytes(sigBytes)
	if err != nil {
		return verifyResult{OK: false}, nil
	}
	return verifyResult{OK: luxbls.Verify(pk, sig, msg)}, nil
}
