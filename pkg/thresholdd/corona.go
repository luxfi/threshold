package thresholdd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"

	corona "github.com/luxfi/ringtail/threshold"
)

// coronaScheme wires the Corona / Ringtail R-LWE threshold kernel
// (luxfi/ringtail/threshold — see protocols/ringtail/ringtail.go) into
// the JSON-RPC surface. Same shape as pulsarScheme: opaque tokens for
// publicKey + signature with live objects held in-memory.
type coronaScheme struct {
	mu         sync.Mutex
	groupKeys  map[string]*coronaSession
	signatures map[string]*coronaSigEntry
}

type coronaSession struct {
	threshold int
	signers   []*corona.Signer
	groupKey  *corona.GroupKey
}

type coronaSigEntry struct {
	sig *corona.Signature
	msg string
	pk  string
}

func newCoronaScheme() *coronaScheme {
	return &coronaScheme{
		groupKeys:  make(map[string]*coronaSession),
		signatures: make(map[string]*coronaSigEntry),
	}
}

func (s *coronaScheme) Keygen(p keygenParams) (keygenResult, error) {
	if err := validateKeygenParams(p); err != nil {
		return keygenResult{}, err
	}
	if p.Threshold >= p.Participants {
		return keygenResult{}, fmt.Errorf("corona: threshold must be < participants (got %d/%d)", p.Threshold, p.Participants)
	}
	shares, gk, err := corona.GenerateKeys(p.Threshold, p.Participants, rand.Reader)
	if err != nil {
		return keygenResult{}, fmt.Errorf("corona keygen: %w", err)
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return keygenResult{}, fmt.Errorf("token: %w", err)
	}
	pkHex := hex.EncodeToString(token)

	signers := make([]*corona.Signer, len(shares))
	for i, sh := range shares {
		signers[i] = corona.NewSigner(sh)
	}

	s.mu.Lock()
	s.groupKeys[pkHex] = &coronaSession{
		threshold: p.Threshold,
		signers:   signers,
		groupKey:  gk,
	}
	s.mu.Unlock()

	shareHex := make([]string, len(shares))
	for i := range shares {
		shareHex[i] = fmt.Sprintf("corona-share-%s-%d", pkHex[:16], i)
	}
	return keygenResult{PublicKey: pkHex, Shares: shareHex}, nil
}

func (s *coronaScheme) Sign(p signParams) (signResult, error) {
	s.mu.Lock()
	sess, ok := s.groupKeys[p.PubKeyHex]
	s.mu.Unlock()
	if !ok {
		return signResult{}, fmt.Errorf("corona sign: unknown pubKeyHex (keygen first)")
	}

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

	r1Data := make(map[int]*corona.Round1Data, t)
	for i, sgn := range signers {
		r1Data[i] = sgn.Round1(sessionID, prfKey, signerIdx)
	}

	message := p.MessageHex

	r2Data := make(map[int]*corona.Round2Data, t)
	for i, sgn := range signers {
		d, err := sgn.Round2(sessionID, message, prfKey, signerIdx, r1Data)
		if err != nil {
			return signResult{}, fmt.Errorf("corona round2 party %d: %w", i, err)
		}
		r2Data[i] = d
	}

	sig, err := signers[0].Finalize(r2Data)
	if err != nil {
		return signResult{}, fmt.Errorf("corona finalize: %w", err)
	}

	tok := make([]byte, 32)
	if _, err := rand.Read(tok); err != nil {
		return signResult{}, fmt.Errorf("sig token: %w", err)
	}
	sigHex := hex.EncodeToString(tok)
	s.mu.Lock()
	s.signatures[sigHex] = &coronaSigEntry{sig: sig, msg: message, pk: p.PubKeyHex}
	s.mu.Unlock()
	return signResult{SignatureHex: sigHex}, nil
}

func (s *coronaScheme) Verify(p verifyParams) (verifyResult, error) {
	s.mu.Lock()
	sess, sessOK := s.groupKeys[p.PubKeyHex]
	entry, sigOK := s.signatures[p.SignatureHex]
	s.mu.Unlock()
	if !sessOK || !sigOK {
		return verifyResult{OK: false}, nil
	}
	if entry.pk != p.PubKeyHex {
		return verifyResult{OK: false}, nil
	}
	if entry.msg != p.MessageHex {
		return verifyResult{OK: false}, nil
	}
	return verifyResult{OK: corona.Verify(sess.groupKey, entry.msg, entry.sig)}, nil
}
