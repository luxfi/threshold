// SPDX-License-Identifier: BSD-3-Clause
package thresholdd

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	coronaThreshold "github.com/luxfi/corona/threshold"

	rlwetee "github.com/luxfi/threshold/protocols/rlwe-tee"
)

// coronaScheme wires luxfi/corona/threshold (Ring-LWE post-quantum
// threshold signatures) into the dispatcher's scheme surface.
//
// Wire-format contract (closed 2026-05-31): the corona kernel now
// publishes canonical MarshalBinary / UnmarshalBinary on Signature and
// GroupKey plus a stateless VerifyBytes(gkBytes, msg, sigBytes) helper.
// Every output of this scheme is bytes that any independent verifier
// holding the published GroupKey bytes can validate.
//
// Trust model on keygen:
//
//   - The dispatcher runs the trusted-dealer GenerateKeys path
//     in-process (this is the dispatcher contract for off-chain test
//     harnesses, NOT the on-chain production path). The Pedersen-DKG
//     no-trusted-dealer path lives at luxfi/corona/keyera.Bootstrap and
//     is what consensus drives at chain genesis. The dispatcher exists
//     for off-chain test harnesses, MPC bus integration tests, and
//     SDK-driven dev tooling — not for chain-genesis ceremonies.
//
// Trust model on sign:
//
//   - The 2-round protocol (Round1 → Round2 → Finalize) runs
//     in-process across all n parties for the session identified by
//     pubKeyHex. The dispatcher returns the aggregated wire bytes;
//     callers MUST verify via VerifyBytes (or the corona kernel's
//     Verify) using ONLY the published GroupKey bytes.
//
// Trust model on verify:
//
//   - Stateless: VerifyBytes(gkBytes, msg, sigBytes). No per-session
//     state is consulted; the supplied GroupKey bytes are the
//     authority.
type coronaScheme struct {
	mu       sync.Mutex
	sessions map[string]*coronaSession

	// teeBackend is the optional institutional-custody R-LWE signer
	// wired via SetTEEBackend. nil → Sign_TEE refuses.
	teeBackend *rlwetee.Signer
}

// errCoronaTEEUnwired is returned by Sign_TEE when no TEE backend is registered.
var errCoronaTEEUnwired = errors.New("corona tee sign: no TEE backend wired (call SetTEEBackend first)")

// coronaSession holds the in-process per-party key shares + group key
// for a single (pubKeyHex) keygen output.
type coronaSession struct {
	threshold int
	gk        *coronaThreshold.GroupKey
	shares    []*coronaThreshold.KeyShare
	signers   []int
	// prfKey is the deterministic PRF key bound to this session.
	// Same key for every sign call against this session so the MAC /
	// noise sampling agree across sign rounds. In production each party
	// derives its own PRF key from an authenticated KEX channel.
	prfKey []byte
	// sessionID counter — incremented per sign call so distinct
	// messages signed under the same group key use distinct sessions
	// (matches the corona kernel's per-signature freshness contract).
	sessionID int
}

func newCoronaScheme() *coronaScheme {
	return &coronaScheme{sessions: make(map[string]*coronaSession)}
}

// Keygen runs corona.threshold.GenerateKeys for t-of-n, publishes
// canonical GroupKey wire bytes as PublicKey, and returns one hex blob
// per party in Shares.
//
// The Shares slice contains the per-party KeyShare INDICES (decimal),
// not the raw secret material. The dispatcher retains the actual
// KeyShare structs in-process keyed by the PublicKey hex; subsequent
// Sign calls reference the session via PubKeyHex. This avoids exposing
// raw share polynomials over the wire, which would otherwise leak the
// secret share material to anyone who can read the response.
func (s *coronaScheme) Keygen(p keygenParams) (keygenResult, error) {
	if err := validateKeygenParams(p); err != nil {
		return keygenResult{}, err
	}
	// corona requires t < n strictly (the kernel enforces this in
	// GenerateKeys: see threshold.go:118).
	if p.Threshold >= p.Participants {
		return keygenResult{}, fmt.Errorf("corona keygen: threshold must be < participants (corona kernel constraint)")
	}

	shares, gk, err := coronaThreshold.GenerateKeys(p.Threshold, p.Participants, rand.Reader)
	if err != nil {
		return keygenResult{}, fmt.Errorf("corona keygen: %w", err)
	}

	gkBytes, err := gk.MarshalBinary()
	if err != nil {
		return keygenResult{}, fmt.Errorf("corona keygen: gk.MarshalBinary: %w", err)
	}
	pkHex := hex.EncodeToString(gkBytes)

	// PRF key — bound to the GroupKey hash so the session can be
	// re-derived (deterministically) if the daemon restarts and rebuilds
	// session state from a persistent store. Today the session is
	// in-memory so the binding is for protocol freshness only.
	hPK := sha256.Sum256(gkBytes)

	signers := make([]int, p.Threshold)
	for i := range signers {
		signers[i] = i
	}

	s.mu.Lock()
	s.sessions[pkHex] = &coronaSession{
		threshold: p.Threshold,
		gk:        gk,
		shares:    shares,
		signers:   signers,
		prfKey:    hPK[:],
		sessionID: 0,
	}
	s.mu.Unlock()

	// Shares array: per-party metadata indices. NOT secret shares.
	// Callers who need to drive the round-based protocol externally use
	// the luxfi/corona/threshold kernel directly (it owns the in-process
	// share representation).
	shareIDs := make([]string, len(shares))
	for i := range shares {
		shareIDs[i] = fmt.Sprintf("%d", shares[i].Index)
	}

	return keygenResult{PublicKey: pkHex, Shares: shareIDs}, nil
}

// Sign drives the 2-round Corona protocol for the t signers in the
// session and returns the aggregated signature wire bytes.
//
// Round1 → Round2 → Finalize all run in-process. The output is byte
// bytes that any caller holding the corresponding GroupKey wire bytes
// can verify via VerifyBytes (or this scheme's Verify op).
func (s *coronaScheme) Sign(p signParams) (signResult, error) {
	msg, err := hex.DecodeString(p.MessageHex)
	if err != nil {
		return signResult{}, fmt.Errorf("messageHex: %w", err)
	}

	s.mu.Lock()
	sess, ok := s.sessions[p.PubKeyHex]
	if !ok {
		s.mu.Unlock()
		return signResult{}, fmt.Errorf("corona sign: unknown pubKeyHex (keygen first)")
	}
	// Bump session counter inside the lock so concurrent Sign calls
	// against the same group key get distinct sessionIDs.
	sess.sessionID++
	sessionID := sess.sessionID
	sessionShares := sess.shares
	sessionGK := sess.gk
	sessionSigners := append([]int(nil), sess.signers...)
	sessionPRF := append([]byte(nil), sess.prfKey...)
	s.mu.Unlock()

	// Build t signers (independent kernel objects per Sign call).
	signers := make([]*coronaThreshold.Signer, len(sessionSigners))
	for i, idx := range sessionSigners {
		signers[i] = coronaThreshold.NewSigner(sessionShares[idx])
	}

	// Round 1: each party broadcasts D matrix + MACs.
	r1Data := make(map[int]*coronaThreshold.Round1Data, len(sessionSigners))
	for _, signer := range signers {
		r1 := signer.Round1(sessionID, sessionPRF, sessionSigners)
		r1Data[r1.PartyID] = r1
	}

	// Round 2: each party broadcasts z share. We use the canonical
	// message-as-string convention (corona kernel signs over a string,
	// not bytes — see Verify signature). The message hex bytes are
	// converted to a string here; collision-free because hex encoding is
	// injective.
	r2Data := make(map[int]*coronaThreshold.Round2Data, len(sessionSigners))
	msgStr := string(msg)
	for _, signer := range signers {
		r2, err := signer.Round2(sessionID, msgStr, sessionPRF, sessionSigners, r1Data)
		if err != nil {
			return signResult{}, fmt.Errorf("corona sign round2: %w", err)
		}
		r2Data[r2.PartyID] = r2
	}

	// Finalize: any party aggregates. Use the first signer.
	sig, err := signers[0].Finalize(r2Data)
	if err != nil {
		return signResult{}, fmt.Errorf("corona sign finalize: %w", err)
	}

	// Sanity check: the signature MUST verify against the group key
	// before we publish it. Refuses to return bytes that would fail at
	// the caller (production-safety belt-and-braces — a failure here
	// signals a kernel bug, not a caller bug).
	if !coronaThreshold.Verify(sessionGK, msgStr, sig) {
		return signResult{}, fmt.Errorf("corona sign: produced signature failed self-verify (kernel bug)")
	}

	sigBytes, err := sig.MarshalBinary()
	if err != nil {
		return signResult{}, fmt.Errorf("corona sign: sig.MarshalBinary: %w", err)
	}
	return signResult{SignatureHex: hex.EncodeToString(sigBytes)}, nil
}

// Verify is stateless: it decodes the supplied GroupKey + Signature
// wire bytes and runs the corona kernel's stateless VerifyBytes.
//
// The dispatcher does NOT consult any in-process session — the
// supplied PubKeyHex IS the authority. This is the contract that
// independent peers (other mpcd, bridge nodes, L1 verifier contracts)
// must satisfy.
func (s *coronaScheme) Verify(p verifyParams) (verifyResult, error) {
	msg, err := hex.DecodeString(p.MessageHex)
	if err != nil {
		return verifyResult{}, fmt.Errorf("messageHex: %w", err)
	}
	sigBytes, err := hex.DecodeString(p.SignatureHex)
	if err != nil {
		return verifyResult{}, fmt.Errorf("signatureHex: %w", err)
	}
	gkBytes, err := hex.DecodeString(p.PubKeyHex)
	if err != nil {
		return verifyResult{}, fmt.Errorf("pubKeyHex: %w", err)
	}
	return verifyResult{OK: coronaThreshold.VerifyBytes(gkBytes, string(msg), sigBytes)}, nil
}

// SetTEEBackend wires a rlwetee.Signer as the institutional-custody
// TEE-gated signing path. The default `corona.sign` procedure is
// UNAFFECTED — it remains the permissionless trusted-dealer 2-round
// threshold path.
//
// Passing nil clears the backend (subsequent Sign_TEE calls return
// errCoronaTEEUnwired).
func (s *coronaScheme) SetTEEBackend(b *rlwetee.Signer) {
	s.mu.Lock()
	s.teeBackend = b
	s.mu.Unlock()
}

// Sign_TEE is the institutional-custody opt-in signing path. Mirrors
// magnetarScheme.Sign_TEE; the inner primitive is corona Ring-LWE
// via the rlwetee.Signer.
//
// Returns the corona-threshold-framed wire signature + the
// SignReceipt audit signature bytes.
func (s *coronaScheme) Sign_TEE(
	ctx context.Context,
	kind string,
	evidenceBytes []byte,
	rim, hardware, teePub [32]byte,
	verifyOpts []TEEVerifyOption,
	jobID [32]byte,
	msg []byte,
) ([]byte, []byte, error) {
	s.mu.Lock()
	b := s.teeBackend
	s.mu.Unlock()
	if b == nil {
		return nil, nil, errCoronaTEEUnwired
	}

	env := &rlwetee.Envelope{
		Kind:          attestKindFromString(kind),
		EvidenceBytes: append([]byte(nil), evidenceBytes...),
		RIM:           rim,
		Hardware:      hardware,
		TEEPub:        teePub,
		VerifyOpts:    teeVerifyOptionsToAttest(verifyOpts),
	}

	wire, receipt, err := b.Sign(ctx, env, jobID, msg)
	if err != nil {
		return nil, nil, fmt.Errorf("corona tee sign: %w", err)
	}
	if receipt == nil {
		return nil, nil, fmt.Errorf("corona tee sign: nil receipt")
	}
	return wire, receipt.AuditSignature, nil
}
