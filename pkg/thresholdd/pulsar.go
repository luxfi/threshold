// SPDX-License-Identifier: BSD-3-Clause
package thresholdd

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	pulsar "github.com/luxfi/pulsar/ref/go/pkg/pulsar"

	mldsatee "github.com/luxfi/threshold/protocols/mldsa-tee"
)

// pulsarScheme wires luxfi/pulsar (Module-LWE FIPS 204 ML-DSA-65
// post-quantum threshold signatures) into the JSON-RPC surface.
//
// Wire-format contract (closed 2026-05-31): pulsar now publishes
// canonical MarshalBinary / UnmarshalBinary on Signature and
// PublicKey (the wire-form group public key, in a PULG frame) plus
// a stateless VerifyBytes(gkBytes, msg, sigBytes) helper. Every
// output of this scheme is bytes that any independent verifier
// holding the published PULG-framed group public key can validate.
// The headline cryptographic claim — that the Pulsar threshold
// signature is bit-identical to a single-party FIPS 204 ML-DSA
// signature on the same (message, group public key) — is pinned
// upstream by TestPulsar_Wire_FIPS204Verifiable, TestAlgebraic_ByteValid,
// and TestAlgebraic_FullCycle_n5_t3.
//
// Trust model on keygen:
//
//   - The dispatcher runs the trusted-dealer
//     pulsar.DealAlgebraicV03Shares path in-process. The v0.3
//     algebraic-aggregate sign path then never reconstructs the
//     master sk anywhere — parties hold polynomial-vector Shamir
//     shares of (s_1, s_2, t_0) over GF(q) and the aggregator
//     combines (z, c·s_2, c·t_0) under Lagrange-linearity
//     (TestAlgebraic_NoSkAccess pins this AST-structurally). This
//     matches corona's symmetric dealer contract: a JSON-RPC
//     dispatcher is for off-chain test harnesses, MPC bus
//     integration tests, and SDK-driven dev tooling — NOT
//     chain-genesis ceremonies. Chain-genesis runs a
//     no-trusted-dealer DKG (pulsar.NewDKGSession), which the
//     dispatcher does NOT expose because the DKG is interactive
//     across messaging rounds and does not fit a single-shot
//     JSON-RPC envelope.
//
// Trust model on sign:
//
//   - The 2-round-with-w-reveal protocol (Round1 → Round2W →
//     Round2Sign → AlgebraicAggregate{,Ctx}) runs in-process across
//     all t signers in the session identified by pubKeyHex via
//     pulsar.OrchestrateV03Sign (empty ctx) or
//     pulsar.OrchestrateV03SignCtx (ctx-bound). Both APIs reduce to
//     the same algebraic-aggregate kernel; the ctx variant threads
//     the FIPS 204 §5.4 octet-string into the SHAKE-256 μ prehash
//     so the output verifies under VerifyCtx(pub, msg, ctx, sig).
//     The dispatcher returns the aggregated PULS-framed wire bytes;
//     callers MUST verify via VerifyBytes (or pulsar.VerifyBytes /
//     pulsar.VerifyCtx) using ONLY the published PULG-framed group
//     public key.
//   - Rejection-restart: FIPS 204's natural restart probability is
//     ~5 attempts; we cap at params.MaxRestart (256, abort
//     probability < 2^-512). The whole loop lives inside
//     OrchestrateV03Sign{,Ctx} so the dispatcher stays thin.
//   - NO master sk is materialised in the dispatcher process at
//     any point during Sign or Sign_Ctx. The historical dealerKey
//     single-party shortcut was deleted at pulsar v1.1.0; both
//     Sign and Sign_Ctx now run the full algebraic-aggregate path.
//     Pinned by TestAlgebraic_NoSkAccess/AlgebraicAggregateCtx in
//     luxfi/pulsar.
//
// Trust model on verify:
//
//   - Stateless: VerifyBytes(gkBytes, msg, sigBytes). No
//     per-session state is consulted; the supplied PULG-framed
//     group public key bytes are the authority.
type pulsarScheme struct {
	mu       sync.Mutex
	sessions map[string]*pulsarSession

	// teeBackend is the optional institutional-custody ML-DSA signer
	// wired via SetTEEBackend. nil → Sign_TEE refuses.
	teeBackend *mldsatee.Signer
}

// errPulsarTEEUnwired is returned by Sign_TEE when no TEE backend is registered.
var errPulsarTEEUnwired = errors.New("pulsar tee sign: no TEE backend wired (call SetTEEBackend first)")

// pulsarSession holds the in-process per-party state for a single
// v0.3 algebraic-aggregate keygen output.
type pulsarSession struct {
	threshold int

	// setup carries the algebraic-aggregate public material (group
	// public key, ρ, tr, A). NO master sk material — enforced
	// AST-structurally by TestAlgebraic_SetupHasNoSkField.
	setup *pulsar.AlgebraicSetup

	// shares are the per-party AlgebraicKeyShare values. The
	// dispatcher retains them in-process; subsequent Sign calls
	// reference the session via pubKeyHex (the PULG-framed group
	// public key bytes). This avoids exposing raw share polynomials
	// over JSON-RPC.
	shares []*pulsar.AlgebraicKeyShare

	// quorum is the canonical t-element committee (sorted by NodeID).
	quorum []pulsar.NodeID

	// quorumShares is shares[0:threshold] cached in the order quorum
	// references them, so Sign can hand them to OrchestrateV03Sign
	// without re-indexing.
	quorumShares []*pulsar.AlgebraicKeyShare

	// evalPoints carries the precomputed Shamir x-coordinates for
	// the quorum (V03QuorumEvalPoints output).
	evalPoints []uint32

	// identities holds each committee member's long-term ML-KEM-768
	// + ML-DSA-65 identity. In production each party would hold its
	// own keypair in HSM; in the dispatcher they all live in-process.
	identities map[pulsar.NodeID]*pulsar.IdentityKey

	// sessionCounter increments per Sign call so distinct messages
	// signed under the same group key use distinct sessionIDs (matches
	// pulsar's per-signature freshness contract). Bumped inside the
	// dispatcher mutex.
	sessionCounter uint64
}

func newPulsarScheme() *pulsarScheme {
	return &pulsarScheme{sessions: make(map[string]*pulsarSession)}
}

// Keygen runs pulsar.DealAlgebraicV03Shares for t-of-n, generates
// per-party long-term identities for the symmetric-session layer,
// publishes the canonical PULG-framed group public key bytes as
// PublicKey, and returns one decimal eval-point per party in Shares.
//
// The Shares slice contains the per-party AlgebraicKeyShare
// eval-point INDICES (decimal), not the raw secret material. The
// dispatcher retains the actual share polynomials in-process keyed
// by the PublicKey hex; subsequent Sign calls reference the session
// via PubKeyHex. This matches the corona scheme's contract.
func (s *pulsarScheme) Keygen(p keygenParams) (keygenResult, error) {
	if err := validateKeygenParams(p); err != nil {
		return keygenResult{}, err
	}

	params := pulsar.MustParamsFor(pulsar.ModeP65)

	// Generate committee NodeIDs deterministically from a fresh
	// session salt. Distinct NodeIDs across sessions so concurrent
	// keygens cannot alias.
	var sessionSalt [32]byte
	if _, err := rand.Read(sessionSalt[:]); err != nil {
		return keygenResult{}, fmt.Errorf("pulsar keygen: salt entropy: %w", err)
	}
	committee := make([]pulsar.NodeID, p.Participants)
	for i := 0; i < p.Participants; i++ {
		var idBuf [4]byte
		binary.BigEndian.PutUint32(idBuf[:], uint32(i+1)) // 1-indexed; index 0 forbidden
		seed := sha256.Sum256(append(append([]byte{}, sessionSalt[:]...), idBuf[:]...))
		committee[i] = pulsar.NodeID(seed)
	}

	// Generate per-party identities (ML-KEM-768 + ML-DSA-65) for the
	// symmetric-session layer that authenticates the round-1 MAC keys.
	identities := make(map[pulsar.NodeID]*pulsar.IdentityKey, len(committee))
	for _, id := range committee {
		ident, err := pulsar.GenerateIdentity(rand.Reader)
		if err != nil {
			return keygenResult{}, fmt.Errorf("pulsar keygen: GenerateIdentity: %w", err)
		}
		identities[id] = ident
	}

	// Master seed for this session — feeds the v0.3 trusted dealer and
	// is wiped immediately after the shares are produced. After this
	// point NO master-sk-bearing material exists anywhere in this
	// process: Sign_Ctx now runs the full algebraic-aggregate threshold
	// loop (pulsar v1.1.0 OrchestrateV03SignCtx), so there is no
	// dispatcher-retained dealerKey to reconstruct sk from.
	var masterSeed [pulsar.SeedSize]byte
	if _, err := rand.Read(masterSeed[:]); err != nil {
		return keygenResult{}, fmt.Errorf("pulsar keygen: master seed entropy: %w", err)
	}
	setup, shares, err := pulsar.DealAlgebraicV03Shares(params, committee, p.Threshold, masterSeed, rand.Reader)
	for i := range masterSeed {
		masterSeed[i] = 0
	}
	if err != nil {
		return keygenResult{}, fmt.Errorf("pulsar keygen: DealAlgebraicV03Shares: %w", err)
	}

	// Canonical quorum: the first t shares (DealAlgebraicV03Shares
	// returns shares in ascending-NodeID order, which matches the
	// canonical quorum order pulsar consumes).
	quorum := make([]pulsar.NodeID, p.Threshold)
	quorumShares := make([]*pulsar.AlgebraicKeyShare, p.Threshold)
	for i := 0; i < p.Threshold; i++ {
		quorum[i] = shares[i].NodeID
		quorumShares[i] = shares[i]
	}
	evalPoints, err := pulsar.V03QuorumEvalPoints(quorum, quorumShares)
	if err != nil {
		return keygenResult{}, fmt.Errorf("pulsar keygen: V03QuorumEvalPoints: %w", err)
	}

	gkBytes, err := setup.Pub.MarshalBinary()
	if err != nil {
		return keygenResult{}, fmt.Errorf("pulsar keygen: setup.Pub.MarshalBinary: %w", err)
	}
	pkHex := hex.EncodeToString(gkBytes)

	s.mu.Lock()
	s.sessions[pkHex] = &pulsarSession{
		threshold:    p.Threshold,
		setup:        setup,
		shares:       shares,
		quorum:       quorum,
		quorumShares: quorumShares,
		evalPoints:   evalPoints,
		identities:   identities,
	}
	s.mu.Unlock()

	shareIDs := make([]string, len(shares))
	for i := range shares {
		shareIDs[i] = fmt.Sprintf("%d", shares[i].EvalPoint)
	}
	return keygenResult{PublicKey: pkHex, Shares: shareIDs}, nil
}

// Sign drives the v0.3 algebraic-aggregate protocol for the t
// signers in the session and returns the PULS-framed signature wire
// bytes. The output is bit-identical to a single-party FIPS 204
// ML-DSA signature on the same (message, group public key) — any
// caller holding the corresponding PULG-framed group public key can
// verify via VerifyBytes (or pulsar.VerifyBytes).
func (s *pulsarScheme) Sign(p signParams) (signResult, error) {
	msg, err := hex.DecodeString(p.MessageHex)
	if err != nil {
		return signResult{}, fmt.Errorf("messageHex: %w", err)
	}

	s.mu.Lock()
	sess, ok := s.sessions[p.PubKeyHex]
	if !ok {
		s.mu.Unlock()
		return signResult{}, fmt.Errorf("pulsar sign: unknown pubKeyHex (keygen first)")
	}
	sess.sessionCounter++
	counter := sess.sessionCounter
	setup := sess.setup
	quorum := append([]pulsar.NodeID(nil), sess.quorum...)
	quorumShares := append([]*pulsar.AlgebraicKeyShare(nil), sess.quorumShares...)
	evalPoints := append([]uint32(nil), sess.evalPoints...)
	identities := sess.identities
	s.mu.Unlock()

	params := pulsar.MustParamsFor(setup.Mode)

	// Build sessionID from the per-session counter; binds this Sign
	// call to a distinct PRNG seed across concurrent Sign calls
	// against the same group key.
	var sessionID [16]byte
	binary.BigEndian.PutUint64(sessionID[:8], counter)
	binary.BigEndian.PutUint64(sessionID[8:], 0xDEADBEEFCAFEBABE) // dispatcher tag

	// Compute pairwise session keys for the quorum (ML-KEM-768
	// encapsulation + ML-DSA-65 authentication per pair).
	sessionKeys, err := pulsar.QuorumSessionKeys(quorum, identities, sessionID, msg)
	if err != nil {
		return signResult{}, fmt.Errorf("pulsar sign: QuorumSessionKeys: %w", err)
	}

	sig, err := pulsar.OrchestrateV03Sign(params, setup, msg, sessionID,
		quorum, quorumShares, evalPoints, sessionKeys, params.MaxRestart, rand.Reader)
	if err != nil {
		return signResult{}, fmt.Errorf("pulsar sign: %w", err)
	}

	// Self-verify safety belt before publishing. Refuses to return
	// bytes that would fail at the caller — a failure here would
	// signal a kernel bug, not a caller bug.
	if err := pulsar.Verify(params, setup.Pub, msg, sig); err != nil {
		return signResult{}, fmt.Errorf("pulsar sign: produced signature failed self-verify (kernel bug): %w", err)
	}

	sigBytes, err := sig.MarshalBinary()
	if err != nil {
		return signResult{}, fmt.Errorf("pulsar sign: sig.MarshalBinary: %w", err)
	}
	return signResult{SignatureHex: hex.EncodeToString(sigBytes)}, nil
}

// Sign_Ctx is the ctx-bound permissionless signing surface for the
// pulsar dispatcher. It emits a FIPS 204 §5.4 context-bound ML-DSA
// signature on (msg, ctx) under the session's group public key, so
// callers can produce signatures that satisfy the on-chain EVM
// precompile's domain-separation contract:
//
//	`lux-evm-precompile-mldsa-v1`   → luxfi/precompile/mldsa
//	(pub.VerifySignatureCtx(msg, sig, ctx))
//
// Wire bytes: PULS-framed (Signature.MarshalBinary) — bit-identical
// to a single-party FIPS 204 §5.4 ctx-bound SignTo on the same
// (master_sk, msg, ctx) tuple. Any FIPS 204 verifier holding the
// session's PULG-framed group public key bytes accepts the result
// under VerifyCtx(pub, msg, ctx, sig).
//
// Path (pulsar v1.1.0+): runs the FULL algebraic-aggregate threshold
// loop via pulsar.OrchestrateV03SignCtx. NO master sk is materialised
// at any point in this process: parties hold polynomial-vector Shamir
// shares of (s_1, s_2, t_0) over GF(q); the aggregator combines
// (z, c·s_2, c·t_0) under Lagrange-linearity; the FIPS 204 §5.4 μ
// prefix carries ctx into the SHAKE-256 prehash so the output is
// byte-identical to single-party SignTo on the (existentially
// quantified) master sk. The historical dealerKey single-party
// shortcut has been deleted.
//
// Compare to Sign_TEE: same ctx semantics, HSM-held sk. Both
// produce wire bytes verifiable under the same PULG-framed group key.
//
// signCtx is the FIPS 204 ctx octet string (0..255 bytes). Pass nil
// (or the empty hex string "") to bind the empty ctx — backwards
// compatible with v0.3 OrchestrateV03Sign byte-for-byte under the
// same deterministic seeds.
//
// NOTE on strict-PQ: this method is the legacy entry point; it does
// NOT consult the strict-PQ profile gate. Callers that produce
// signatures destined for a strict-PQ chain MUST go through the
// JSON-RPC dispatcher (which routes via Sign_Ctx_Profile and runs
// the gate). In-process callers that want the gate consult
// RefuseUnderStrictPQ themselves before invoking Sign_Ctx.
func (s *pulsarScheme) Sign_Ctx(p signCtxParams) (signResult, error) {
	return s.signCtxInternal(p)
}

// Sign_Ctx_Profile is the profile-aware entry point. The dispatcher
// always routes here when the scheme implements
// profileAwareCtxSigner (see server.go). The gate fires at entry:
// on a strict-PQ chain, the call is refused with
// ErrRefusedUnderStrictPQ (HTTP 503 + documented body); on any
// other profile, or with no resolver / no chain ID, the call falls
// through to signCtxInternal.
//
// Why the gate sits HERE (not in signCtxInternal): the legacy
// Sign_Ctx is still public for in-process embedders that have
// their own outer admission gate (e.g. luxfi/mpc's API surface).
// Forcing the gate on every caller would surprise those. The
// dispatcher path — the one network-reachable surface — always
// runs the gate. One function, one place: profile.go owns the
// policy; this method owns the call site.
//
// HISTORY: this gate guarded the dealer-shortcut shortcut (pulsar
// v1.0.x) where a single-party PrivateKey lived in pulsarSession.
// pulsar v1.1.0 deleted dealerKey; signCtxInternal now runs the
// full algebraic-aggregate threshold path with NO sk-bearing state
// in process. The strict-PQ refusal is therefore now a POLICY gate
// (operators may still want to refuse v1 ML-DSA on a strict-PQ
// chain in favour of v0.4 hybrid composition), not a cryptographic
// gate against sk leakage. We KEEP IT — strict-PQ semantics is a
// chain-level policy choice, not a kernel claim.
func (s *pulsarScheme) Sign_Ctx_Profile(p signCtxParams, resolver ChainProfileResolver) (signResult, error) {
	if err := RefuseUnderStrictPQ(p.ChainID, "pulsar.sign_ctx", resolver); err != nil {
		return signResult{}, err
	}
	return s.signCtxInternal(p)
}

// signCtxInternal is the v1.1.0 ctx-bound algebraic-aggregate path.
// Drives the full Round1 → Round2W → Round2Sign → AlgebraicAggregateCtx
// loop with the supplied ctx threaded into the FIPS 204 §5.4 step-2 μ
// prehash. NO master sk is materialised at any point in this function
// or in the per-party state machines — parties hold polynomial-vector
// Shamir shares of (s_1, s_2, t_0) over GF(q); the aggregator combines
// (z, c·s_2, c·t_0) under Lagrange-linearity (TestAlgebraic_NoSkAccess/
// AlgebraicAggregateCtx pins this AST-structurally upstream).
//
// The empty-ctx case (CtxHex == "") is byte-identical to Sign(msg) —
// pulsar.OrchestrateV03Sign is now a wrapper around
// OrchestrateV03SignCtx(nil, msg).
func (s *pulsarScheme) signCtxInternal(p signCtxParams) (signResult, error) {
	msg, err := hex.DecodeString(p.MessageHex)
	if err != nil {
		return signResult{}, fmt.Errorf("messageHex: %w", err)
	}
	var signCtx []byte
	if p.CtxHex != "" {
		signCtx, err = hex.DecodeString(p.CtxHex)
		if err != nil {
			return signResult{}, fmt.Errorf("ctxHex: %w", err)
		}
	}

	s.mu.Lock()
	sess, ok := s.sessions[p.PubKeyHex]
	if !ok {
		s.mu.Unlock()
		return signResult{}, fmt.Errorf("pulsar sign_ctx: unknown pubKeyHex (keygen first)")
	}
	sess.sessionCounter++
	counter := sess.sessionCounter
	setup := sess.setup
	quorum := append([]pulsar.NodeID(nil), sess.quorum...)
	quorumShares := append([]*pulsar.AlgebraicKeyShare(nil), sess.quorumShares...)
	evalPoints := append([]uint32(nil), sess.evalPoints...)
	identities := sess.identities
	s.mu.Unlock()

	params := pulsar.MustParamsFor(setup.Mode)

	// Build sessionID from the per-session counter; binds this Sign_Ctx
	// call to a distinct PRNG seed across concurrent calls against the
	// same group key. The trailing 8 bytes tag this as the ctx-bound
	// dispatcher path so a captured wire trace is unambiguously
	// attributable to Sign_Ctx vs Sign.
	var sessionID [16]byte
	binary.BigEndian.PutUint64(sessionID[:8], counter)
	binary.BigEndian.PutUint64(sessionID[8:], 0xC1C1BAB1ECAFE505) // sign_ctx tag

	// Compute pairwise session keys for the quorum (ML-KEM-768
	// encapsulation + ML-DSA-65 authentication per pair). The
	// transcript MUST bind the message but NOT the ctx — session
	// keys are per-(sid, msg); ctx enters at the μ derivation
	// inside the v0.4 algebraic-aggregate loop.
	sessionKeys, err := pulsar.QuorumSessionKeys(quorum, identities, sessionID, msg)
	if err != nil {
		return signResult{}, fmt.Errorf("pulsar sign_ctx: QuorumSessionKeys: %w", err)
	}

	sig, err := pulsar.OrchestrateV03SignCtx(params, setup, signCtx, msg, sessionID,
		quorum, quorumShares, evalPoints, sessionKeys, params.MaxRestart, rand.Reader)
	if err != nil {
		return signResult{}, fmt.Errorf("pulsar sign_ctx: %w", err)
	}

	// Self-verify safety belt: refuse to publish bytes that would
	// fail at the caller. Uses pulsar.VerifyCtx so ctx-binding is
	// covered.
	if err := pulsar.VerifyCtx(params, setup.Pub, msg, signCtx, sig); err != nil {
		return signResult{}, fmt.Errorf("pulsar sign_ctx: produced signature failed self-verify (kernel bug): %w", err)
	}

	sigBytes, err := sig.MarshalBinary()
	if err != nil {
		return signResult{}, fmt.Errorf("pulsar sign_ctx: sig.MarshalBinary: %w", err)
	}
	return signResult{SignatureHex: hex.EncodeToString(sigBytes)}, nil
}

// Verify is stateless: it decodes the supplied PULG-framed group
// public key + PULS-framed signature wire bytes and runs the
// pulsar kernel's stateless VerifyBytes.
//
// The dispatcher does NOT consult any in-process session — the
// supplied PubKeyHex IS the authority. This is the contract that
// independent peers (other mpcd, bridge nodes, L1 verifier
// contracts) must satisfy.
func (s *pulsarScheme) Verify(p verifyParams) (verifyResult, error) {
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
	return verifyResult{OK: pulsar.VerifyBytes(gkBytes, msg, sigBytes)}, nil
}

// SetTEEBackend wires a mldsatee.Signer as the institutional-custody
// TEE-gated signing path. The default JSON-RPC `pulsar.sign` method
// is UNAFFECTED — it remains the permissionless v0.3 algebraic-
// aggregate path.
//
// Passing nil clears the backend (subsequent Sign_TEE calls return
// errPulsarTEEUnwired).
func (s *pulsarScheme) SetTEEBackend(b *mldsatee.Signer) {
	s.mu.Lock()
	s.teeBackend = b
	s.mu.Unlock()
}

// Sign_TEE is the institutional-custody opt-in signing path. Mirrors
// magnetarScheme.Sign_TEE; the inner primitive is FIPS 204 ML-DSA via
// the mldsatee.Signer.
//
// Returns the PULS-framed wire signature + the SignReceipt audit
// signature bytes.
func (s *pulsarScheme) Sign_TEE(
	ctx context.Context,
	kind string,
	evidenceBytes []byte,
	rim, hardware, teePub [32]byte,
	verifyOpts []TEEVerifyOption,
	jobID [32]byte,
	msg []byte,
	signCtx []byte,
) ([]byte, []byte, error) {
	s.mu.Lock()
	b := s.teeBackend
	s.mu.Unlock()
	if b == nil {
		return nil, nil, errPulsarTEEUnwired
	}

	env := &mldsatee.Envelope{
		Kind:          attestKindFromString(kind),
		EvidenceBytes: append([]byte(nil), evidenceBytes...),
		RIM:           rim,
		Hardware:      hardware,
		TEEPub:        teePub,
		VerifyOpts:    teeVerifyOptionsToAttest(verifyOpts),
	}

	wire, receipt, err := b.Sign(ctx, env, jobID, msg, signCtx)
	if err != nil {
		return nil, nil, fmt.Errorf("pulsar tee sign: %w", err)
	}
	if receipt == nil {
		return nil, nil, fmt.Errorf("pulsar tee sign: nil receipt")
	}
	return wire, receipt.AuditSignature, nil
}
