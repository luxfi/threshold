package thresholdd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/cmp"
	cmpconfig "github.com/luxfi/threshold/protocols/cmp/config"
)

// cggmp21Scheme wires luxfi/threshold/protocols/cmp (the CGGMP21 fork
// the threshold repo ships — see protocols/cmp/CLAUDE.md) into the
// JSON-RPC surface.
//
// Keygen simulates `participants` parties in-process, runs the CGGMP21
// keygen protocol, and indexes the resulting per-party Configs by the
// compressed public key. Sign re-uses those Configs to drive the 4-round
// sign protocol with the first `threshold` parties as signers.
type cggmp21Scheme struct {
	mu       sync.Mutex
	sessions map[string]*cggmp21Session // key = compressed pubkey hex
}

type cggmp21Session struct {
	threshold int
	configs   map[party.ID]*cmpconfig.Config
	partyIDs  []party.ID
}

func newCGGMP21Scheme() *cggmp21Scheme {
	return &cggmp21Scheme{sessions: make(map[string]*cggmp21Session)}
}

func (s *cggmp21Scheme) Keygen(p keygenParams) (keygenResult, error) {
	if err := validateKeygenParams(p); err != nil {
		return keygenResult{}, err
	}
	group := curve.Secp256k1{}
	ids := partyIDs(p.Participants)
	// Per-party pool, matching the working cmp_basic_test pattern.
	pools := make(map[party.ID]*pool.Pool, len(ids))
	for _, id := range ids {
		pools[id] = pool.NewPool(0)
	}
	defer func() {
		for _, pl := range pools {
			pl.TearDown()
		}
	}()

	sessionID := []byte(fmt.Sprintf("cggmp21-keygen-%d", time.Now().UnixNano()))
	results, err := runMultiparty(ids, sessionID, func(id party.ID) protocol.StartFunc {
		return cmp.Keygen(group, id, ids, p.Threshold-1, pools[id])
	}, 5*time.Minute)
	if err != nil {
		return keygenResult{}, fmt.Errorf("cggmp21 keygen: %w", err)
	}

	configs := make(map[party.ID]*cmpconfig.Config, len(ids))
	for _, id := range ids {
		c, ok := results[id].(*cmpconfig.Config)
		if !ok {
			return keygenResult{}, fmt.Errorf("cggmp21 keygen: party %s produced %T not *cmp.Config", id, results[id])
		}
		configs[id] = c
	}

	pub := configs[ids[0]].PublicPoint()
	pkBytes, err := pub.MarshalBinary()
	if err != nil {
		return keygenResult{}, fmt.Errorf("marshal pubkey: %w", err)
	}
	pkHex := hex.EncodeToString(pkBytes)

	// Index by pubkey for subsequent sign() calls. Shares are returned
	// as the per-party ECDSA secret-share scalar — opaque to callers,
	// but consistent with the registry contract.
	shares := make([]string, 0, len(ids))
	for _, id := range ids {
		sh, err := configs[id].ECDSA.MarshalBinary()
		if err != nil {
			return keygenResult{}, fmt.Errorf("marshal share: %w", err)
		}
		shares = append(shares, hex.EncodeToString(sh))
	}

	s.mu.Lock()
	s.sessions[pkHex] = &cggmp21Session{
		threshold: p.Threshold,
		configs:   configs,
		partyIDs:  ids,
	}
	s.mu.Unlock()

	return keygenResult{PublicKey: pkHex, Shares: shares}, nil
}

func (s *cggmp21Scheme) Sign(p signParams) (signResult, error) {
	msg, err := hex.DecodeString(p.MessageHex)
	if err != nil {
		return signResult{}, fmt.Errorf("messageHex: %w", err)
	}
	s.mu.Lock()
	sess, ok := s.sessions[p.PubKeyHex]
	s.mu.Unlock()
	if !ok {
		return signResult{}, fmt.Errorf("cggmp21 sign: unknown pubKeyHex (keygen first)")
	}

	// Hash the message — CGGMP21 sign consumes a fixed-length hash.
	hash := sha256.Sum256(msg)

	signers := sess.partyIDs[:sess.threshold]
	pools := make(map[party.ID]*pool.Pool, len(signers))
	for _, id := range signers {
		pools[id] = pool.NewPool(0)
	}
	defer func() {
		for _, pl := range pools {
			pl.TearDown()
		}
	}()

	sessionID := []byte(fmt.Sprintf("cggmp21-sign-%d", time.Now().UnixNano()))
	results, err := runMultiparty(signers, sessionID, func(id party.ID) protocol.StartFunc {
		return cmp.Sign(sess.configs[id], signers, hash[:], pools[id])
	}, 5*time.Minute)
	if err != nil {
		return signResult{}, fmt.Errorf("cggmp21 sign: %w", err)
	}

	sig, ok := results[signers[0]].(*ecdsa.Signature)
	if !ok {
		return signResult{}, fmt.Errorf("cggmp21 sign: party %s produced %T not *ecdsa.Signature", signers[0], results[signers[0]])
	}

	rBytes, err := sig.R.MarshalBinary()
	if err != nil {
		return signResult{}, fmt.Errorf("marshal R: %w", err)
	}
	sBytes, err := sig.S.MarshalBinary()
	if err != nil {
		return signResult{}, fmt.Errorf("marshal S: %w", err)
	}
	// Wire: R (33 compressed) || S (32) = 65 bytes.
	out := append(rBytes, sBytes...)
	return signResult{SignatureHex: hex.EncodeToString(out)}, nil
}

func (s *cggmp21Scheme) Verify(p verifyParams) (verifyResult, error) {
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
	if len(sigBytes) != 65 {
		return verifyResult{OK: false}, nil
	}
	sig := ecdsa.EmptySignature(group)
	if err := sig.R.UnmarshalBinary(sigBytes[:33]); err != nil {
		return verifyResult{OK: false}, nil
	}
	if err := sig.S.UnmarshalBinary(sigBytes[33:]); err != nil {
		return verifyResult{OK: false}, nil
	}
	pub := group.NewPoint()
	if err := pub.UnmarshalBinary(pkBytes); err != nil {
		return verifyResult{OK: false}, nil
	}
	hash := sha256.Sum256(msg)
	return verifyResult{OK: sig.Verify(pub, hash[:])}, nil
}
