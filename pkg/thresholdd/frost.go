package thresholdd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/frost"
	frostkeygen "github.com/luxfi/threshold/protocols/frost/keygen"
	frostsign "github.com/luxfi/threshold/protocols/frost/sign"
)

// frostScheme wires luxfi/threshold/protocols/frost (RFC 9591) into
// the JSON-RPC surface. secp256k1 group only — the registry's policyId
// is "SCHNORR-SECP256K1-FROST-RFC9591".
type frostScheme struct {
	mu       sync.Mutex
	sessions map[string]*frostSession
}

type frostSession struct {
	threshold int
	configs   map[party.ID]*frostkeygen.Config
	partyIDs  []party.ID
}

func newFrostScheme() *frostScheme {
	return &frostScheme{sessions: make(map[string]*frostSession)}
}

func (s *frostScheme) Keygen(p keygenParams) (keygenResult, error) {
	if err := validateKeygenParams(p); err != nil {
		return keygenResult{}, err
	}
	group := curve.Secp256k1{}
	ids := partyIDs(p.Participants)
	sessionID := []byte(fmt.Sprintf("frost-keygen-%d", time.Now().UnixNano()))
	results, err := runMultiparty(ids, sessionID, func(id party.ID) protocol.StartFunc {
		// FROST threshold semantics: threshold parties can sign together,
		// so the "t" passed into Keygen is threshold-1 (max-corruptions).
		return frost.Keygen(group, id, ids, p.Threshold-1)
	}, 2*time.Minute)
	if err != nil {
		return keygenResult{}, fmt.Errorf("frost keygen: %w", err)
	}

	configs := make(map[party.ID]*frostkeygen.Config, len(ids))
	for _, id := range ids {
		c, ok := results[id].(*frostkeygen.Config)
		if !ok {
			return keygenResult{}, fmt.Errorf("frost keygen: party %s produced %T", id, results[id])
		}
		configs[id] = c
	}
	pkBytes, err := configs[ids[0]].PublicKey.MarshalBinary()
	if err != nil {
		return keygenResult{}, fmt.Errorf("marshal pubkey: %w", err)
	}
	pkHex := hex.EncodeToString(pkBytes)

	shares := make([]string, 0, len(ids))
	for _, id := range ids {
		sh, err := configs[id].PrivateShare.MarshalBinary()
		if err != nil {
			return keygenResult{}, fmt.Errorf("marshal share: %w", err)
		}
		shares = append(shares, hex.EncodeToString(sh))
	}

	s.mu.Lock()
	s.sessions[pkHex] = &frostSession{
		threshold: p.Threshold,
		configs:   configs,
		partyIDs:  ids,
	}
	s.mu.Unlock()

	return keygenResult{PublicKey: pkHex, Shares: shares}, nil
}

func (s *frostScheme) Sign(p signParams) (signResult, error) {
	msg, err := hex.DecodeString(p.MessageHex)
	if err != nil {
		return signResult{}, fmt.Errorf("messageHex: %w", err)
	}
	s.mu.Lock()
	sess, ok := s.sessions[p.PubKeyHex]
	s.mu.Unlock()
	if !ok {
		return signResult{}, fmt.Errorf("frost sign: unknown pubKeyHex (keygen first)")
	}
	// FROST consumes a message hash (32 bytes).
	hash := sha256.Sum256(msg)

	signers := sess.partyIDs[:sess.threshold]
	sessionID := []byte(fmt.Sprintf("frost-sign-%d", time.Now().UnixNano()))
	results, err := runMultiparty(signers, sessionID, func(id party.ID) protocol.StartFunc {
		return frost.Sign(sess.configs[id], signers, hash[:])
	}, 2*time.Minute)
	if err != nil {
		return signResult{}, fmt.Errorf("frost sign: %w", err)
	}
	sigVal, ok := results[signers[0]].(frostsign.Signature)
	if !ok {
		return signResult{}, fmt.Errorf("frost sign: party %s produced %T", signers[0], results[signers[0]])
	}
	sigBytes, err := sigVal.MarshalBinary()
	if err != nil {
		return signResult{}, fmt.Errorf("marshal signature: %w", err)
	}
	return signResult{SignatureHex: hex.EncodeToString(sigBytes)}, nil
}

func (s *frostScheme) Verify(p verifyParams) (verifyResult, error) {
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
	group := curve.Secp256k1{}
	pub := group.NewPoint()
	if err := pub.UnmarshalBinary(pkBytes); err != nil {
		return verifyResult{OK: false}, nil
	}
	var sig frostsign.Signature
	if err := sig.UnmarshalBinary(group, sigBytes); err != nil {
		return verifyResult{OK: false}, nil
	}
	hash := sha256.Sum256(msg)
	return verifyResult{OK: sig.Verify(pub, hash[:])}, nil
}
