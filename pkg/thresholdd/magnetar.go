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

	magnetar "github.com/luxfi/magnetar/ref/go/pkg/magnetar"

	slhdsatee "github.com/luxfi/threshold/protocols/slhdsa-tee"
)

// magnetarScheme wires luxfi/magnetar (FIPS 205 SLH-DSA, hash-based
// post-quantum signature) into the dispatcher's scheme surface.
//
// Wire-format contract (closed 2026-05-31): magnetar now publishes
// canonical MarshalBinary / UnmarshalGroupKey on Signature and
// PublicKey (the wire-form group public key, in a MAGG frame) plus
// a stateless VerifyBytes(gkBytes, msg, sigBytes) helper. Every
// output of this scheme is bytes that any independent verifier
// holding the published MAGG-framed group public key can validate.
// The headline cryptographic claim — that the magnetar signature is
// byte-identical to a single-party FIPS 205 SLH-DSA signature on
// the same (message, group public key) — is pinned upstream by
// TestMagnetar_Wire_FIPS205Verifiable.
//
// Magnetar architectural framing (v0.5+ CHANGELOG):
//
//   - PRIMARY public-BFT primitive: per-validator standalone
//     SLH-DSA. Each validator holds its OWN keypair (sk_i, pk_i),
//     produces a single-party FIPS 205 signature σ_i, and the
//     consensus layer collects N signatures into a
//     ValidatorAggregateCert. NO DKG, NO dealer, NO aggregator-in-
//     TCB. This is the canonical v0.5 primary path.
//   - CUSTODY (TEE-required): magnetar.CombineWithSeedReconstruction
//     (v0.1 reveal-and-aggregate) — produces one FIPS 205-shaped σ
//     by reconstructing the master seed in aggregator memory. NOT
//     public-BFT-safe (the aggregator is in the TCB). Off the bus.
//
// What this dispatcher exposes:
//
//   - The PRIMARY per-validator standalone path is the dispatcher
//     surface. Keygen generates `participants` independent SLH-DSA
//     keypairs; the dispatcher retains them all keyed by the FIRST
//     validator's MAGG-framed public-key hex; Sign returns the FIRST
//     validator's MAGS-framed signature.
//   - The wire bytes are byte-identical to single-party FIPS 205 on
//     the (msg, pk_0) pair — verifiable by any external party with
//     a FIPS 205 verifier and the documented MAGG / MAGS frame.
//   - The N-of-N collected-signatures form (ValidatorAggregateCert)
//     is not on the dispatcher surface today because the bus shape
//     (one signature per .sign call) doesn't naturally carry N
//     parallel signatures. That form is the consensus-layer's job;
//     embedders that need it call magnetar.BuildAggregateCert /
//     VerifyAggregateCert directly.
//
// Trust model:
//
//   - On keygen: the dispatcher generates N independent per-
//     validator keypairs in-process. The N-1 non-signing keypairs
//     are retained alongside the canonical one so future bus
//     extensions (e.g. a parallel-slices cert form) can use them
//     without re-keygen. For the test surface here, the FIRST
//     validator is the canonical signer.
//   - On sign: a single FIPS 205 SignDeterministic call under the
//     first validator's seed (the magnetar.ValidatorSign primary
//     primitive). Output is byte-identical to circl/slhdsa output
//     on the same (sk, msg) pair — no ctx is bound (callers needing
//     ctx must use magnetar.Sign directly with the precompile ctx).
//   - On verify: stateless. magnetar.VerifyBytes(gkBytes, msg,
//     sigBytes). No per-session state is consulted; the supplied
//     MAGG bytes are the authority.
type magnetarScheme struct {
	mu       sync.Mutex
	sessions map[string]*magnetarSession

	// teeBackend is the optional institutional-custody SLH-DSA
	// signer wired via SetTEEBackend. When nil, Sign_TEE refuses
	// with errMagnetarTEEUnwired. The default permissionless path
	// (Sign) is unaffected by the TEE backend's presence — UNLESS
	// the chain profile is strict-PQ, in which case Sign itself
	// refuses (see profile gate below).
	teeBackend *slhdsatee.Signer

	// pool is the optional t-of-n attested-combiner pool. When the
	// chain profile is strict-PQ AND the pool is wired, Combine_TEE
	// routes through the pool's t-of-n agreement. When the pool is
	// nil but profile is strict-PQ, Combine_TEE refuses with
	// ErrMagnetarNoTEEAttestation.
	pool *slhdsatee.CombinerPool

	// profile is the chain-security profile this dispatcher is
	// bound to. Default is ProfileLegacyCompat (commodity-host
	// strict-atom Combine is acceptable). Strict-PQ chains MUST
	// call SetChainSecurityProfile at boot to flip this value;
	// once flipped, the permissionless Sign path refuses with
	// ErrMagnetarNoTEEAttestation and only Sign_TEE / Combine_TEE
	// produce signatures.
	//
	// Hickey discipline: profile is ONE value in ONE place. The
	// gate is the single function magnetarRefuseUnderStrictPQ.
	// The dispatcher reads it the same way the precompile
	// contract.RefuseUnderStrictPQ helper reads its
	// StrictPQReporter: ONE function, ONE place, ONE canonical
	// refusal sentinel.
	profile slhdsatee.ChainSecurityProfile
}

// errMagnetarTEEUnwired is returned by Sign_TEE when no TEE backend
// has been registered via SetTEEBackend.
var errMagnetarTEEUnwired = errors.New("magnetar tee sign: no TEE backend wired (call SetTEEBackend first)")

// errMagnetarPoolUnwired is returned by Combine_TEE when no combiner
// pool has been registered via SetCombinerPool, regardless of profile.
var errMagnetarPoolUnwired = errors.New("magnetar combine_tee: no combiner pool wired (call SetCombinerPool first)")

// magnetarSession holds the in-process per-validator keypairs for
// one Keygen output. The canonical PublicKey for the session is the
// MAGG-framed wire bytes of `keys[0].pk`; subsequent Sign calls
// reference this session via PubKeyHex.
type magnetarSession struct {
	mode magnetar.Mode

	// keys are the N per-validator keypairs. Index 0 is the
	// canonical signer (the one whose pk is published as the
	// session's PublicKey on the dispatcher surface). Indices 1..N-1
	// are retained for future cert-form bus extensions.
	keys []magnetarKeypair
}

type magnetarKeypair struct {
	sk *magnetar.PrivateKey
	pk *magnetar.PublicKey
}

func newMagnetarScheme() *magnetarScheme {
	return &magnetarScheme{sessions: make(map[string]*magnetarSession)}
}

// errMagnetarUnknownSession is returned when Sign is called against
// a pubKeyHex no Keygen has produced.
var errMagnetarUnknownSession = errors.New("magnetar sign: unknown pubKeyHex (keygen first)")

// Keygen generates `participants` independent per-validator SLH-DSA
// keypairs via the magnetar v0.5 PerValidatorKeypair primary
// primitive (no DKG, no shared seed, no aggregator). The session is
// retained in-process keyed by the FIRST validator's MAGG-framed
// public-key hex. The Shares slice carries the 1-indexed validator
// indices (decimal) so the test surface gets per-participant share
// IDs even though the underlying scheme is N independent keypairs.
//
// Mode: ModeM192s (SHAKE-192s, NIST PQ category 3) is the dispatcher
// default — recommended in magnetar's CHANGELOG and matched by the
// canonical 8-step gate orchestrator. Callers needing M192f or M256s
// must instantiate magnetar directly.
func (s *magnetarScheme) Keygen(p keygenParams) (keygenResult, error) {
	if err := validateKeygenParams(p); err != nil {
		return keygenResult{}, err
	}
	if p.Participants > 0xFF {
		// We pack the validator index into a single byte of the
		// per-keypair seed. Up to 255 validators per Keygen is more
		// than enough for the dispatcher's off-chain test harness
		// surface; for larger committees use the magnetar package
		// directly.
		return keygenResult{}, fmt.Errorf("magnetar keygen: participants=%d exceeds dispatcher limit 255", p.Participants)
	}

	params := magnetar.MustParamsFor(magnetar.ModeM192s)

	// Generate per-validator seed material derived from a fresh
	// session salt + per-validator index. This is internal to the
	// dispatcher and does NOT escape to the wire — each PrivateKey
	// generated here is a stock FIPS 205 SLH-DSA keypair. The
	// salt ensures concurrent Keygen calls do not produce identical
	// keypairs.
	var sessionSalt [32]byte
	if _, err := rand.Read(sessionSalt[:]); err != nil {
		return keygenResult{}, fmt.Errorf("magnetar keygen: salt entropy: %w", err)
	}

	keys := make([]magnetarKeypair, p.Participants)
	for i := 0; i < p.Participants; i++ {
		// Deterministic per-validator RNG seeded by (sessionSalt ||
		// big-endian validator index). The underlying
		// PerValidatorKeypair call reads params.SeedSize bytes from
		// this RNG; supplying a deterministic stream lets the
		// dispatcher re-derive identical keys if needed (e.g. for
		// debugging). Production deployments would use
		// crypto/rand directly per validator.
		seedMix := append([]byte(nil), sessionSalt[:]...)
		var idxBuf [4]byte
		binary.BigEndian.PutUint32(idxBuf[:], uint32(i+1))
		seedMix = append(seedMix, idxBuf[:]...)
		sk, pk, err := magnetar.PerValidatorKeypair(params, &magnetarSeededReader{seed: seedMix})
		if err != nil {
			return keygenResult{}, fmt.Errorf("magnetar keygen: PerValidatorKeypair[%d]: %w", i, err)
		}
		keys[i] = magnetarKeypair{sk: sk, pk: pk}
	}

	// Publish the FIRST validator's public key as the session's
	// canonical MAGG-framed wire bytes.
	gkBytes, err := magnetar.MarshalGroupKey(keys[0].pk)
	if err != nil {
		return keygenResult{}, fmt.Errorf("magnetar keygen: MarshalGroupKey: %w", err)
	}
	pkHex := hex.EncodeToString(gkBytes)

	s.mu.Lock()
	s.sessions[pkHex] = &magnetarSession{mode: params.Mode, keys: keys}
	s.mu.Unlock()

	shareIDs := make([]string, p.Participants)
	for i := 0; i < p.Participants; i++ {
		shareIDs[i] = fmt.Sprintf("%d", i+1)
	}
	return keygenResult{PublicKey: pkHex, Shares: shareIDs}, nil
}

// magnetarRefuseUnderStrictPQ is the profile gate for the magnetar
// dispatcher. ONE function, ONE place — mirrors
// precompile/contract.RefuseUnderStrictPQ at the precompile layer.
//
// Returns slhdsatee.ErrMagnetarNoTEEAttestation when the dispatcher
// is bound to ProfileStrictPQ. Returns nil otherwise.
//
// Called at the top of Sign / Sign_Ctx (the permissionless paths)
// — under strict-PQ, the permissionless path is hard-refused; only
// Sign_TEE / Combine_TEE can produce signatures because only those
// paths route the master-seed reconstruction through an attested
// TEE.
//
// Read under the dispatcher's mutex so SetChainSecurityProfile can
// flip the gate atomically at boot.
func (s *magnetarScheme) magnetarRefuseUnderStrictPQ() error {
	s.mu.Lock()
	p := s.profile
	s.mu.Unlock()
	if p == slhdsatee.ProfileStrictPQ {
		return slhdsatee.ErrMagnetarNoTEEAttestation
	}
	return nil
}

// SetChainSecurityProfile binds the dispatcher to one of the
// canonical chain-security profiles. Strict-PQ chains MUST call
// this at boot with slhdsatee.ProfileStrictPQ; the default value
// (slhdsatee.ProfileLegacyCompat) preserves the commodity-host
// permissionless Sign path.
//
// Idempotent — re-issuing the same profile is a no-op. Operators
// rotating a chain into strict-PQ MUST follow the cascade:
//   - flip the chain profile in luxfi/node ChainConfig
//   - flip this dispatcher's profile via SetChainSecurityProfile
//   - wire a CombinerPool via SetCombinerPool (>= Threshold attested
//     members already provisioned).
//
// Until all three steps complete, the dispatcher will refuse Sign
// AND Combine_TEE on the strict-PQ chain — fail-closed under
// half-rotated state.
func (s *magnetarScheme) SetChainSecurityProfile(p slhdsatee.ChainSecurityProfile) {
	s.mu.Lock()
	s.profile = p
	s.mu.Unlock()
}

// SetCombinerPool wires the t-of-n attested-combiner pool. Required
// for Combine_TEE under any profile; under strict-PQ, it is the
// canonical sign surface.
func (s *magnetarScheme) SetCombinerPool(p *slhdsatee.CombinerPool) {
	s.mu.Lock()
	s.pool = p
	s.mu.Unlock()
}

// Sign produces a magnetar signature for the message under the
// session's canonical (FIRST) validator keypair, frames it in the
// MAGS wire codec, and returns the wire bytes as hex. Output is
// byte-identical to single-party FIPS 205 SLH-DSA SignDeterministic
// on the (sk_0, message, ctx=nil) tuple — pinned upstream by
// TestMagnetar_Wire_FIPS205Verifiable.
//
// The signing path runs magnetar.ValidatorSign with rng=nil, which
// is the v0.5 canonical public-BFT signing primitive. ctx is
// intentionally omitted here (the bus shape does not carry one);
// the published bytes verify under VerifyBytes with the same MAGG
// public-key bytes plus the original message.
//
// Profile gate: when the dispatcher is bound to
// slhdsatee.ProfileStrictPQ, Sign refuses with
// ErrMagnetarNoTEEAttestation — the permissionless path is hard-
// refused on strict-PQ chains. Callers MUST use Sign_TEE
// (single-host attested) or Combine_TEE (t-of-n attested pool).
func (s *magnetarScheme) Sign(p signParams) (signResult, error) {
	if err := s.magnetarRefuseUnderStrictPQ(); err != nil {
		return signResult{}, err
	}
	msg, err := hex.DecodeString(p.MessageHex)
	if err != nil {
		return signResult{}, fmt.Errorf("messageHex: %w", err)
	}

	s.mu.Lock()
	sess, ok := s.sessions[p.PubKeyHex]
	s.mu.Unlock()
	if !ok {
		return signResult{}, errMagnetarUnknownSession
	}

	if len(sess.keys) == 0 {
		// Defence in depth: should not happen — Keygen rejects
		// participants <= 0 — but a corrupted session map should
		// not be sign-oraclable.
		return signResult{}, fmt.Errorf("magnetar sign: empty session")
	}

	sigBytes, err := magnetar.ValidatorSign(sess.keys[0].sk, nil, msg)
	if err != nil {
		return signResult{}, fmt.Errorf("magnetar sign: ValidatorSign: %w", err)
	}

	sig := &magnetar.Signature{Mode: sess.mode, Bytes: sigBytes}

	// Self-verify safety belt before publishing. Refuses to return
	// bytes that would fail at the caller — a failure here would
	// signal a kernel bug, not a caller bug. Mirrors pulsar's
	// dispatcher discipline.
	params := magnetar.MustParamsFor(sess.mode)
	if err := magnetar.Verify(params, sess.keys[0].pk, msg, sig); err != nil {
		return signResult{}, fmt.Errorf("magnetar sign: produced signature failed self-verify (kernel bug): %w", err)
	}

	wireBytes, err := sig.MarshalBinary()
	if err != nil {
		return signResult{}, fmt.Errorf("magnetar sign: sig.MarshalBinary: %w", err)
	}
	return signResult{SignatureHex: hex.EncodeToString(wireBytes)}, nil
}

// Sign_Ctx is the ctx-bound permissionless signing surface for the
// magnetar dispatcher. It emits a FIPS 205 §10.2 context-bound
// SLH-DSA signature on (msg, ctx) under the session's canonical
// per-validator keypair (keys[0]), so callers can produce signatures
// that satisfy the on-chain EVM precompile's domain-separation
// contract:
//
//	`lux-evm-precompile-slhdsa-v1`   → luxfi/precompile/slhdsa
//	(pub.VerifySignatureCtx(msg, sig, ctx))
//
// Wire bytes: MAGS-framed (Signature.MarshalBinary) — byte-identical
// to a single-party FIPS 205 SignDeterministic on the same (sk, msg,
// ctx) tuple. Any FIPS 205 verifier holding the session's MAGG-framed
// group public key bytes accepts the result.
//
// Path: routes through magnetar.SignCtx on the dispatcher-retained
// per-validator standalone keypair (sess.keys[0].sk). The magnetar
// v0.5 primary primitive is already single-party-per-validator (no
// MPC aggregation), so the ctx binding flows straight through circl
// slhdsa.SignDeterministic with no kernel extension required.
//
// signCtx is the FIPS 205 ctx octet string (0..255 bytes). Pass nil
// (or the empty hex string "") to bind the empty ctx — semantically
// equivalent to Sign.
//
// Profile gate: same as Sign — refuses under strict-PQ with
// ErrMagnetarNoTEEAttestation when the scheme has been bound to
// slhdsatee.ProfileStrictPQ via SetChainSecurityProfile. Callers
// MUST use Sign_TEE for ctx-bound institutional-custody signing on
// strict-PQ chains.
//
// NOTE: this method does NOT consult the per-request chain-ID
// resolver gate (RefuseUnderStrictPQ in profile.go). Callers that
// reach this method via the ZAP dispatcher go through
// Sign_Ctx_Profile (where the resolver gate fires before this);
// in-process callers with their own outer admission gate may
// bypass the resolver gate.
func (s *magnetarScheme) Sign_Ctx(p signCtxParams) (signResult, error) {
	return s.signCtxInternal(p)
}

// Sign_Ctx_Profile is the magnetar profile-aware entry point.
// Same shape as pulsar.Sign_Ctx_Profile: the per-request chain-ID
// resolver gate fires first, then the scheme-bound slhdsatee gate
// (inside signCtxInternal). Two orthogonal axes:
//
//   - resolver gate: "does the request's chain ID resolve to
//     strict-PQ?" — refuses with ErrRefusedUnderStrictPQ which the
//     ZAP dispatcher surfaces as an error response with
//     strictPQ=true so the client can errors.Is the sentinel.
//   - slhdsatee scheme gate: "is THIS process bound to strict-PQ
//     via SetChainSecurityProfile?" — refuses with
//     ErrMagnetarNoTEEAttestation surfaced as a ZapErrCodeInternal
//     error. Pre-dates this gate; remains for back-compat with
//     operators who set the scheme profile but did not wire a
//     resolver.
//
// One function, one place: profile.go::RefuseUnderStrictPQ owns
// the resolver policy; signCtxInternal owns the scheme-bound
// policy. They compose without coupling.
//
// Removal contract: when the magnetar aggregate-cert ctx-bound
// path lands AND signCtxInternal swaps to drive that path with NO
// single-validator shortcut, the resolver gate here becomes dead
// code. Sign_Ctx_Profile then collapses to
// `return s.signCtxInternal(p)`.
func (s *magnetarScheme) Sign_Ctx_Profile(p signCtxParams, resolver ChainProfileResolver) (signResult, error) {
	if err := RefuseUnderStrictPQ(p.ChainID, "magnetar.sign_ctx", resolver); err != nil {
		return signResult{}, err
	}
	return s.signCtxInternal(p)
}

// signCtxInternal is the actual ctx-bound sign path. Runs the
// scheme-bound slhdsatee strict-PQ gate first (refuses with
// ErrMagnetarNoTEEAttestation under SetChainSecurityProfile
// strict-PQ), then drives magnetar.SignCtx on the canonical
// single-validator keypair sess.keys[0].sk. Wire shape is
// MAGS-framed FIPS 205 ctx-bound bytes.
func (s *magnetarScheme) signCtxInternal(p signCtxParams) (signResult, error) {
	if err := s.magnetarRefuseUnderStrictPQ(); err != nil {
		return signResult{}, err
	}
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
		return signResult{}, errMagnetarUnknownSession
	}
	if len(sess.keys) == 0 {
		return signResult{}, fmt.Errorf("magnetar sign_ctx: empty session")
	}

	params := magnetar.MustParamsFor(sess.mode)

	// Deterministic (randomized=false, rng=nil) so the output is
	// KAT-shaped and byte-stable across retries — mirrors Sign and
	// Sign_TEE's SignDeterministic discipline.
	sig, err := magnetar.SignCtx(params, sess.keys[0].sk, msg, signCtx, false, nil)
	if err != nil {
		return signResult{}, fmt.Errorf("magnetar sign_ctx: %w", err)
	}

	// Self-verify safety belt against kernel bugs, using the
	// ctx-aware verifier so any future ctx-propagation regression
	// fails here, not at the caller.
	if err := magnetar.VerifyCtx(params, sess.keys[0].pk, msg, signCtx, sig); err != nil {
		return signResult{}, fmt.Errorf("magnetar sign_ctx: produced signature failed self-verify (kernel bug): %w", err)
	}

	wireBytes, err := sig.MarshalBinary()
	if err != nil {
		return signResult{}, fmt.Errorf("magnetar sign_ctx: sig.MarshalBinary: %w", err)
	}
	return signResult{SignatureHex: hex.EncodeToString(wireBytes)}, nil
}

// Verify is stateless: it decodes the supplied MAGG-framed group
// public key + MAGS-framed signature wire bytes and runs the
// magnetar kernel's stateless VerifyBytes.
//
// The dispatcher does NOT consult any in-process session — the
// supplied PubKeyHex IS the authority. This is the contract that
// independent peers (other mpcd, bridge nodes, L1 verifier
// contracts) must satisfy.
func (s *magnetarScheme) Verify(p verifyParams) (verifyResult, error) {
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
	return verifyResult{OK: magnetar.VerifyBytes(gkBytes, msg, sigBytes)}, nil
}

// SetTEEBackend wires a slhdsatee.Signer as the institutional-custody
// TEE-gated signing path. The default `magnetar.sign` procedure is
// UNAFFECTED — it remains the permissionless per-validator standalone
// path. Operators that need attested release must call SetTEEBackend
// at boot and use Sign_TEE.
//
// Passing nil clears the backend (subsequent Sign_TEE calls return
// errMagnetarTEEUnwired).
func (s *magnetarScheme) SetTEEBackend(b *slhdsatee.Signer) {
	s.mu.Lock()
	s.teeBackend = b
	s.mu.Unlock()
}

// Sign_TEE is the institutional-custody opt-in signing path. It
// chains the supplied attestation evidence + RIM + hardware
// fingerprint + TEE pubkey through the slhdsatee.Signer and emits
// the MAGS-framed FIPS 205 wire bytes on success.
//
// Wire payload:
//
//   - kind          : attest.Kind ("sev_snp", "tdx", "nras")
//   - evidenceBytes : the vendor-framed quote / report
//   - rim           : 32-byte operator-asserted RIM digest
//   - hardware      : 32-byte hardware fingerprint
//   - teePub        : 32-byte X25519 TEE public key
//   - jobID         : 32-byte audit-binding identifier
//   - msg           : message bytes
//   - signCtx       : FIPS 205 §10.2 context (nil for empty)
//
// All inputs are required. The TEE backend (set via SetTEEBackend)
// internally calls approval.ApproveIntent, kms.ReleaseGate.Issue /
// Release, hsm.Provider.GetKey, and magnetar.Sign. Output bytes are
// byte-identical to single-party FIPS 205 SignDeterministic on the
// HSM-stored master seed.
//
// Returns the MAGS-framed wire signature + the SignReceipt's audit
// signature bytes for the embedder's audit log; the receipt itself
// (epoch, ephemeralPub, etc.) is intentionally not surfaced here —
// this dispatcher returns only bytes that participate in verification.
func (s *magnetarScheme) Sign_TEE(
	ctx context.Context,
	kind string,
	evidenceBytes []byte,
	rim, hardware, teePub [32]byte,
	verifyOpts []slhdsateeVerifyOpt,
	jobID [32]byte,
	msg []byte,
	signCtx []byte,
) ([]byte, []byte, error) {
	s.mu.Lock()
	b := s.teeBackend
	s.mu.Unlock()
	if b == nil {
		return nil, nil, errMagnetarTEEUnwired
	}

	env := &slhdsatee.Envelope{
		Kind:          attestKindFromString(kind),
		EvidenceBytes: append([]byte(nil), evidenceBytes...),
		RIM:           rim,
		Hardware:      hardware,
		TEEPub:        teePub,
		VerifyOpts:    teeVerifyOptionsToAttest(verifyOpts),
	}

	wire, receipt, err := b.Sign(ctx, env, jobID, msg, signCtx)
	if err != nil {
		return nil, nil, fmt.Errorf("magnetar tee sign: %w", err)
	}
	if receipt == nil {
		return nil, nil, fmt.Errorf("magnetar tee sign: nil receipt")
	}
	return wire, receipt.AuditSignature, nil
}

// PoolCombineMember names a single combiner participating in a
// Combine_TEE call. The dispatcher carries the per-member attestation
// payload through to the slhdsatee.CombinerPool.Combine call.
type PoolCombineMember struct {
	// Name is the pool-registered member identifier
	// (matches CombinerPool.AddMember(name, ...)).
	Name string

	// Kind / EvidenceBytes / RIM / Hardware / TEEPub mirror the
	// Sign_TEE payload shape. One PoolCombineMember per member
	// participating in the t-of-n quorum.
	Kind          string
	EvidenceBytes []byte
	RIM           [32]byte
	Hardware      [32]byte
	TEEPub        [32]byte
}

// Combine_TEE is the canonical strict-PQ signing surface. It drives
// the wired CombinerPool's t-of-n attested-combiner Sign and returns
// the agreed wire bytes + per-member audit signatures.
//
// Hard requirements (no caveat path):
//
//   - Pool MUST be wired via SetCombinerPool. errMagnetarPoolUnwired
//     otherwise.
//   - At least pool.Threshold() members MUST appear in `members` AND
//     pass the pool's freshness gate. Otherwise: slhdsatee.
//     ErrMagnetarInsufficientQuorum / ErrMagnetarStaleAttestation.
//   - All selected members MUST produce byte-identical wire output.
//     Divergence: slhdsatee.ErrMagnetarSignatureDivergence.
//
// Output: the consolidated wire signature (byte-equal across the
// quorum) + the per-member audit-signature bytes concatenated as a
// list. Embedders that need the full SignReceipt list call the pool
// directly via SetCombinerPool / pool.Combine — the dispatcher
// surface emits only the bytes that participate in verification
// (the FIPS 205 wire) + the audit trail for control-plane logging.
func (s *magnetarScheme) Combine_TEE(
	ctx context.Context,
	members []PoolCombineMember,
	verifyOpts []slhdsateeVerifyOpt,
	jobID [32]byte,
	msg []byte,
	signCtx []byte,
) ([]byte, [][]byte, error) {
	s.mu.Lock()
	pool := s.pool
	s.mu.Unlock()
	if pool == nil {
		return nil, nil, errMagnetarPoolUnwired
	}

	envs := make(map[string]*slhdsatee.Envelope, len(members))
	for _, m := range members {
		if m.Name == "" {
			return nil, nil, fmt.Errorf("magnetar combine_tee: member with empty Name")
		}
		envs[m.Name] = &slhdsatee.Envelope{
			Kind:          attestKindFromString(m.Kind),
			EvidenceBytes: append([]byte(nil), m.EvidenceBytes...),
			RIM:           m.RIM,
			Hardware:      m.Hardware,
			TEEPub:        m.TEEPub,
			VerifyOpts:    teeVerifyOptionsToAttest(verifyOpts),
		}
	}

	wire, receipts, err := pool.Combine(ctx, envs, jobID, msg, signCtx)
	if err != nil {
		return nil, nil, fmt.Errorf("magnetar combine_tee: %w", err)
	}
	if len(receipts) == 0 {
		return nil, nil, fmt.Errorf("magnetar combine_tee: pool returned no receipts")
	}
	audits := make([][]byte, 0, len(receipts))
	for _, r := range receipts {
		if r == nil {
			return nil, nil, fmt.Errorf("magnetar combine_tee: pool returned nil receipt")
		}
		audits = append(audits, r.AuditSignature)
	}
	return wire, audits, nil
}

// AttestCombinerMember refreshes one pool member's attestation
// freshness state. Called by the operator's control plane out-of-
// band of any sign call; the Combine_TEE path then reads the
// freshness state without performing any KDS / PCS / NRAS network
// roundtrip.
//
// The dispatcher proxies straight through to CombinerPool.Attest;
// the call returns slhdsatee sentinels (ErrAttestationRequired etc.)
// untouched so callers can errors.Is them.
func (s *magnetarScheme) AttestCombinerMember(
	ctx context.Context,
	memberName string,
	kind string,
	evidenceBytes []byte,
	rim, hardware, teePub [32]byte,
	verifyOpts []slhdsateeVerifyOpt,
) error {
	s.mu.Lock()
	pool := s.pool
	s.mu.Unlock()
	if pool == nil {
		return errMagnetarPoolUnwired
	}
	env := &slhdsatee.Envelope{
		Kind:          attestKindFromString(kind),
		EvidenceBytes: append([]byte(nil), evidenceBytes...),
		RIM:           rim,
		Hardware:      hardware,
		TEEPub:        teePub,
		VerifyOpts:    teeVerifyOptionsToAttest(verifyOpts),
	}
	return pool.Attest(ctx, memberName, env)
}

// magnetarSeededReader is a tiny SHA-256-counter deterministic byte
// stream used to seed per-validator keygen inside the dispatcher.
// It is NOT a CSPRNG; it is the dispatcher's internal mechanism for
// turning a session salt + validator index into params.SeedSize
// bytes of fresh-looking key material. The output of this reader
// NEVER escapes the dispatcher — keys[i] holds the resulting FIPS
// 205 keypair, which IS the production wire form.
//
// We intentionally do NOT reach for the magnetar package's
// detReader (it lives under *_test.go and is not exported).
type magnetarSeededReader struct {
	seed []byte
	buf  []byte
	off  int
	ctr  uint32
}

func (r *magnetarSeededReader) Read(p []byte) (int, error) {
	for n := 0; n < len(p); {
		if r.off >= len(r.buf) {
			h := sha256.Sum256(append(append([]byte(nil), r.seed...),
				byte(r.ctr>>24), byte(r.ctr>>16), byte(r.ctr>>8), byte(r.ctr)))
			r.buf = h[:]
			r.off = 0
			r.ctr++
		}
		c := copy(p[n:], r.buf[r.off:])
		n += c
		r.off += c
	}
	return len(p), nil
}
