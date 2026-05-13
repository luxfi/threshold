package thresholdd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"

	pulsar "github.com/luxfi/corona/threshold"
)

// pulsarScheme wires the Pulsar M-LWE threshold kernel (luxfi/corona/threshold
// — the Pulsar fork that powers protocols/pulsar; see protocols/pulsar/doc.go
// for the math kernel vs. round-orchestration split).
//
// Pulsar's Signature and GroupKey types are not byte-serializable as
// stable public encodings; the daemon therefore mints opaque tokens
// (random 32 bytes) as the wire-level publicKey / signature handles
// and keeps the live objects in an in-memory map. This is process-local
// IPC — tokens are not durable across daemon restarts.
type pulsarScheme struct {
	mu         sync.Mutex
	groupKeys  map[string]*pulsarSession
	signatures map[string]*pulsarSigEntry
}

type pulsarSession struct {
	threshold int
	signers   []*pulsar.Signer
	groupKey  *pulsar.GroupKey
	pkToken   []byte
}

type pulsarSigEntry struct {
	sig *pulsar.Signature
	msg string // original message string used for verify
	pk  string // bound pubkey hex
}

func newPulsarScheme() *pulsarScheme {
	return &pulsarScheme{
		groupKeys:  make(map[string]*pulsarSession),
		signatures: make(map[string]*pulsarSigEntry),
	}
}

func (s *pulsarScheme) Keygen(p keygenParams) (keygenResult, error) {
	if err := validateKeygenParams(p); err != nil {
		return keygenResult{}, err
	}
	if p.Threshold >= p.Participants {
		// Pulsar/Corona GenerateKeys requires t < n strictly.
		return keygenResult{}, fmt.Errorf("pulsar: threshold must be < participants (got %d/%d)", p.Threshold, p.Participants)
	}
	shares, gk, err := pulsar.GenerateKeys(p.Threshold, p.Participants, rand.Reader)
	if err != nil {
		return keygenResult{}, fmt.Errorf("pulsar keygen: %w", err)
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return keygenResult{}, fmt.Errorf("token: %w", err)
	}
	pkHex := hex.EncodeToString(token)

	signers := make([]*pulsar.Signer, len(shares))
	for i, sh := range shares {
		signers[i] = pulsar.NewSigner(sh)
	}

	s.mu.Lock()
	s.groupKeys[pkHex] = &pulsarSession{
		threshold: p.Threshold,
		signers:   signers,
		groupKey:  gk,
		pkToken:   token,
	}
	s.mu.Unlock()

	// Shares are also tokens (no stable encoding) — keep a per-party
	// SHA-derived handle so callers see something deterministic.
	shareHex := make([]string, len(shares))
	for i := range shares {
		shareHex[i] = fmt.Sprintf("pulsar-share-%s-%d", pkHex[:16], i)
	}
	return keygenResult{PublicKey: pkHex, Shares: shareHex}, nil
}

func (s *pulsarScheme) Sign(p signParams) (signResult, error) {
	s.mu.Lock()
	sess, ok := s.groupKeys[p.PubKeyHex]
	s.mu.Unlock()
	if !ok {
		return signResult{}, fmt.Errorf("pulsar sign: unknown pubKeyHex (keygen first)")
	}

	// Drive the in-process 2-round Pulsar signing flow across threshold parties.
	t := sess.threshold
	signers := sess.signers[:t]
	signerIdx := make([]int, t)
	for i := 0; i < t; i++ {
		signerIdx[i] = i
	}
	sessionID := 1
	prfKey := make([]byte, 32)
	if _, err := rand.Read(prfKey); err != nil {
		return signResult{}, fmt.Errorf("prfKey: %w", err)
	}

	r1Data := make(map[int]*pulsar.Round1Data, t)
	for i, sgn := range signers {
		r1Data[i] = sgn.Round1(sessionID, prfKey, signerIdx)
	}

	// Pulsar's threshold.Round2 consumes the message as a Go string.
	// The wire format takes hex bytes; convert to canonical hex string.
	message := p.MessageHex

	r2Data := make(map[int]*pulsar.Round2Data, t)
	for i, sgn := range signers {
		d, err := sgn.Round2(sessionID, message, prfKey, signerIdx, r1Data)
		if err != nil {
			return signResult{}, fmt.Errorf("pulsar round2 party %d: %w", i, err)
		}
		r2Data[i] = d
	}

	sig, err := signers[0].Finalize(r2Data)
	if err != nil {
		return signResult{}, fmt.Errorf("pulsar finalize: %w", err)
	}

	// Mint a signature token and stash the live object for verify().
	tok := make([]byte, 32)
	if _, err := rand.Read(tok); err != nil {
		return signResult{}, fmt.Errorf("sig token: %w", err)
	}
	sigHex := hex.EncodeToString(tok)
	s.mu.Lock()
	s.signatures[sigHex] = &pulsarSigEntry{sig: sig, msg: message, pk: p.PubKeyHex}
	s.mu.Unlock()
	return signResult{SignatureHex: sigHex}, nil
}

func (s *pulsarScheme) Verify(p verifyParams) (verifyResult, error) {
	s.mu.Lock()
	sess, sessOK := s.groupKeys[p.PubKeyHex]
	entry, sigOK := s.signatures[p.SignatureHex]
	s.mu.Unlock()
	if !sessOK || !sigOK {
		// Unknown token (or wrong pubkey) → not verified. Matches the
		// teleport mock's "wrong pubkey" expectation.
		return verifyResult{OK: false}, nil
	}
	if entry.pk != p.PubKeyHex {
		return verifyResult{OK: false}, nil
	}
	if entry.msg != p.MessageHex {
		// Forgery / different-message verify must fail.
		return verifyResult{OK: false}, nil
	}
	return verifyResult{OK: pulsar.Verify(sess.groupKey, entry.msg, entry.sig)}, nil
}
