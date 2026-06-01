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
//     Round2Sign → AlgebraicAggregate) runs in-process across all
//     t signers in the session identified by pubKeyHex via
//     pulsar.OrchestrateV03Sign. The dispatcher returns the
//     aggregated PULS-framed wire bytes; callers MUST verify via
//     VerifyBytes (or pulsar.VerifyBytes) using ONLY the published
//     PULG-framed group public key.
//   - Rejection-restart: FIPS 204's natural restart probability is
//     ~5 attempts; we cap at params.MaxRestart (256, abort
//     probability < 2^-512). The whole loop lives inside
//     OrchestrateV03Sign so the dispatcher stays thin.
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

	// dealerKey is the single-party FIPS 204 ML-DSA private key
	// derived from the same master seed that fed the v0.3 trusted
	// dealer. Its public key is BIT-EQUAL to setup.Pub.Bytes (both
	// flow through deriveKeyMaterial → mldsa{44,65,87}.NewKeyFromSeed),
	// so any ctx-bound signature produced via this key verifies under
	// the v0.3 PULG-framed group public key.
	//
	// Sign_Ctx routes through this key to bind FIPS 204 §5.2 ctx
	// (e.g. `lux-evm-precompile-mldsa-v1`) into the signature —
	// upstream pulsar v0.3 OrchestrateV03Sign hardcodes empty ctx
	// (threshold_v03.go: μ = SHAKE-256(tr || 0x00 || 0x00 || M, 64))
	// and ctx-aware THRESHOLD signing is a v0.4 deliverable. Until
	// then the precompile-verifiable surface uses the dispatcher's
	// trusted-dealer privilege: same key, same wire bytes any FIPS 204
	// verifier accepts, just bypassing the algebraic-aggregate path.
	//
	// Trust model: this materialises sk in-process for the lifetime of
	// the session, which the v0.3 threshold path explicitly does NOT.
	// The dispatcher's documented role is off-chain test harnesses /
	// dev tooling / SDK-driven flows — not chain-genesis ceremonies —
	// so the trade-off is acceptable. Production operators that must
	// not hold master sk in-process use Sign_TEE (HSM-held seed).
	dealerKey *pulsar.PrivateKey
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

	// Master seed for this session — used both to (a) deal v0.3
	// algebraic shares and (b) derive a single-party PrivateKey for
	// the Sign_Ctx path. The PrivateKey carries its own copy of the
	// seed; the local masterSeed buffer is wiped immediately after
	// derivation.
	var masterSeed [pulsar.SeedSize]byte
	if _, err := rand.Read(masterSeed[:]); err != nil {
		return keygenResult{}, fmt.Errorf("pulsar keygen: master seed entropy: %w", err)
	}
	dealerKey, err := pulsar.KeyFromSeed(params, masterSeed)
	if err != nil {
		for i := range masterSeed {
			masterSeed[i] = 0
		}
		return keygenResult{}, fmt.Errorf("pulsar keygen: KeyFromSeed: %w", err)
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
		dealerKey:    dealerKey,
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
// pulsar dispatcher. It emits a FIPS 204 §5.2 context-bound ML-DSA
// signature on (msg, ctx) under the session's group public key, so
// callers can produce signatures that satisfy the on-chain EVM
// precompile's domain-separation contract:
//
//	`lux-evm-precompile-mldsa-v1`   → luxfi/precompile/mldsa
//	(pub.VerifySignatureCtx(msg, sig, ctx))
//
// Wire bytes: PULS-framed (Signature.MarshalBinary) — bit-identical
// to a single-party FIPS 204 SignDeterministic on the same (sk, msg,
// ctx) tuple. Any FIPS 204 verifier holding the session's PULG-framed
// group public key bytes accepts the result.
//
// Path: routes through pulsar.Sign on the dispatcher-retained
// dealerKey (see pulsarSession.dealerKey). This bypasses the v0.3
// algebraic-aggregate threshold loop because v0.3 hardcodes empty
// ctx (μ = SHAKE-256(tr || 0x00 || 0x00 || M, 64); ctx-aware
// threshold sign is a v0.4 deliverable upstream). The dispatcher's
// trusted-dealer role makes the single-party shortcut sound: the
// dealerKey's pubkey IS bit-equal to the v0.3 setup.Pub bytes.
//
// Compare to Sign_TEE: same ctx semantics, HSM-held sk. Both
// produce wire bytes verifiable under the same PULG-framed group key.
//
// signCtx is the FIPS 204 ctx octet string (0..255 bytes). Pass nil
// (or the empty hex string "") to bind the empty ctx — semantically
// equivalent to Sign, but emitted via the single-party path.
func (s *pulsarScheme) Sign_Ctx(p signCtxParams) (signResult, error) {
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
	s.mu.Unlock()
	if !ok {
		return signResult{}, fmt.Errorf("pulsar sign_ctx: unknown pubKeyHex (keygen first)")
	}
	if sess.dealerKey == nil {
		// Defence in depth: every Keygen sets dealerKey. A nil here
		// would mean session-map corruption — refuse rather than
		// silently fall back.
		return signResult{}, fmt.Errorf("pulsar sign_ctx: session missing dealerKey")
	}

	params := pulsar.MustParamsFor(sess.setup.Mode)

	// Deterministic (randomized=false) so the output is KAT-shaped
	// and byte-stable across retries — mirrors Sign_TEE's
	// SignDeterministic discipline.
	sig, err := pulsar.Sign(params, sess.dealerKey, msg, signCtx, false, nil)
	if err != nil {
		return signResult{}, fmt.Errorf("pulsar sign_ctx: %w", err)
	}

	// Self-verify safety belt: refuse to publish bytes that would
	// fail at the caller. Uses pulsar.VerifyCtx so ctx-binding is
	// covered.
	if err := pulsar.VerifyCtx(params, sess.setup.Pub, msg, signCtx, sig); err != nil {
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
