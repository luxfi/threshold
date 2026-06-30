// SPDX-License-Identifier: BSD-3-Clause
package thresholdd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"

	pulsar "github.com/luxfi/pulsar/pkg/pulsar"
)

// pulsarScheme wires luxfi/pulsar (Module-LWE FIPS 204 ML-DSA-65
// post-quantum threshold signatures) into the dispatcher's scheme surface.
//
// Wire-format contract: pulsar publishes canonical MarshalBinary /
// UnmarshalBinary on Signature and PublicKey (the wire-form group public
// key, in a PULG frame) plus a stateless VerifyBytes(gkBytes, msg,
// sigBytes) helper. Every output of this scheme is bytes that any
// independent verifier holding the published PULG-framed group public
// key can validate. The headline cryptographic claim — that the Pulsar
// threshold signature is bit-identical to a single-party FIPS 204
// ML-DSA-65 signature on the same (message, group public key) — is
// pinned upstream by TestHyperballStockCirclVerify (the no-reconstruct
// hyperball output verifies under unmodified cloudflare/circl
// mldsa65.Verify).
//
// ----------------------------------------------------------------------
// Trust model on KEYGEN — DEALERLESS RSS (Mithril, ePrint 2026/013).
// ----------------------------------------------------------------------
//
//   - The dispatcher runs the dealerless Replicated-Secret-Sharing key
//     generation (pulsar.MithrilRSSKeygen). There is NO trusted dealer:
//     each of the n parties contributes a fresh seed, the joint public
//     seed rho is derived from every contribution, and the composite
//     ML-DSA secret is the SUM of the C(N,M) per-subset short secrets,
//     each sampled by its subset's leader and replicated only to that
//     subset's members. With T ≥ 2 no single party is a member of every
//     subset, so NO party ever holds the whole (s1, s2). The published
//     group public key (rho ‖ t1) is a genuine FIPS 204 ML-DSA-65 public
//     key whose t1 is exactly what cloudflare/circl derives from
//     (rho, s1, s2). The viability bound (2 ≤ t ≤ n and the norm budget
//     τ·C·η < γ2) is enforced inside MithrilRSSKeygen and surfaced here
//     as a keygen error — fail-closed, never a silent downgrade.
//
// ----------------------------------------------------------------------
// Trust model on SIGN — t-of-n, NO-RECONSTRUCT (Mithril 3-round hyperball).
// ----------------------------------------------------------------------
//
//   - Signing drives pulsar.MithrilKey.SignHyperball: the Mithril 3-round
//     hyperball protocol across the t active parties. Each active party
//     holds ONLY its balanced-partition share s1_(j) and emits ONLY its
//     partial response z_j = y_j + c·s1_(j); the coordinator sums
//     z = Σ_j z_j = y + c·s1 and recovers the FIPS 204 hint from the
//     PUBLIC w' = A·z − c·t1·2^d exactly as a verifier would. NO party
//     and NO coordinator ever forms the full s1, s2, t0, the mask y, the
//     commitment w, w0 = LowBits(w), or any ML-DSA secret key. This is a
//     genuine no-reconstruct threshold signature — strictly stronger than
//     the prior reconstruct-at-combine path (which transiently
//     materialised the master sk in the combiner's memory). SignHyperball
//     fail-closed self-verifies the summed signature under the FIPS 204
//     verifier before returning, so a biased or malformed partial can
//     never yield a bad signature on the wire.
//
//   - A single party CANNOT produce the signature alone: a sub-threshold
//     active set is disjoint from at least one subset whose fresh short
//     secret masks the key, so the threshold guarantee is genuine.
//
//   - One ctx-aware path. The plain Sign (empty ctx) and the ctx-bound
//     Sign_Ctx collapse into a single hyperballSign helper that threads
//     the FIPS 204 §5.2 ctx octet string into SignHyperball; ctx=nil
//     yields the empty-context signature. The dispatcher returns the
//     PULS-framed wire bytes; callers verify via VerifyBytes (empty ctx)
//     or pulsar.VerifyCtx (ctx-bound) using ONLY the published PULG-framed
//     group public key.
//
// ----------------------------------------------------------------------
// Trust model on VERIFY.
// ----------------------------------------------------------------------
//
//   - Stateless: VerifyBytes(gkBytes, msg, sigBytes). No per-session
//     state is consulted; the supplied PULG-framed group public key
//     bytes are the authority. This is the contract independent peers
//     (other mpcd, bridge nodes, on-chain verifier precompiles) satisfy.
type pulsarScheme struct {
	mu       sync.Mutex
	sessions map[string]*pulsarSession
}

// pulsarSession holds the in-process state produced by one dealerless RSS
// keygen, keyed in the scheme by the PULG-framed group public key hex.
type pulsarSession struct {
	// key is the dealerless RSS threshold ML-DSA-65 key. It carries the
	// committee shape (key.T, key.N), the genuine FIPS 204 public key
	// (key.Pub()), and the per-party subset holdings the hyperball signer
	// addresses by party index. SignHyperball reads it without mutation,
	// so concurrent signs under the same group key are safe.
	key *pulsar.MithrilKey

	// gpk is the published PULG-framed group public key bytes — the
	// stateless-verify authority and the source of this session's map key.
	gpk []byte
}

// pulsarHyperballMaxRounds bounds the Mithril 3-round hyperball re-runs
// (each round fans kReps parallel commitment slots) before signing aborts.
// 64 is the value the upstream gate TestHyperballStockCirclVerify proves
// sufficient across every viable committee up to n=8; exhaustion at this
// bound indicates a degenerate RNG, never a forged or invalid signature.
const pulsarHyperballMaxRounds = 64

func newPulsarScheme() *pulsarScheme {
	return &pulsarScheme{sessions: make(map[string]*pulsarSession)}
}

// Keygen runs the DEALERLESS RSS key generation (pulsar.MithrilRSSKeygen)
// for t-of-n at ML-DSA-65, publishes the canonical PULG-framed group
// public key bytes as PublicKey, and returns one party-index per
// committee member in Shares.
//
// NO trusted dealer: every party contributes a fresh seed and the
// composite secret is the sum of per-subset short secrets, no single
// party of which holds the whole (s1, s2). The dispatcher retains the
// resulting MithrilKey in-process keyed by the PublicKey hex; subsequent
// Sign calls reference the session via PubKeyHex. Raw share material (the
// per-subset secrets) never crosses the wire — the Shares slice carries
// only party indices.
func (s *pulsarScheme) Keygen(p keygenParams) (keygenResult, error) {
	if err := validateKeygenParams(p); err != nil {
		return keygenResult{}, err
	}
	t, n := p.Threshold, p.Participants

	// One ≥32-byte contributed seed per party. MithrilRSSKeygen derives
	// the joint public seed rho and each subset's short secret from these;
	// no single party's seed determines the group key.
	partySeeds := make([][]byte, n)
	for i := range partySeeds {
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			return keygenResult{}, fmt.Errorf("pulsar keygen: party %d seed entropy: %w", i, err)
		}
		partySeeds[i] = seed
	}

	// Dealerless RSS keygen. MithrilRSSKeygen runs rss.ValidateCommittee
	// internally and fails CLOSED outside the Mithril viability bound
	// (2 ≤ t ≤ n, norm budget τ·C·η < γ2) — surface that as the keygen
	// error rather than letting a non-viable committee proceed.
	mk, err := pulsar.MithrilRSSKeygen(pulsar.ModeP65, t, n, partySeeds)
	if err != nil {
		return keygenResult{}, fmt.Errorf("pulsar keygen: MithrilRSSKeygen(t=%d,n=%d): %w", t, n, err)
	}

	// Publish the PULG-framed group public key (the FIPS 204 ML-DSA-65 pub
	// rho‖t1 inside a PULG frame). This is the stateless-verify authority.
	gpkPub := &pulsar.PublicKey{Mode: mk.Mode, Bytes: mk.Pub()}
	gkBytes, err := gpkPub.MarshalBinary()
	if err != nil {
		return keygenResult{}, fmt.Errorf("pulsar keygen: group public key MarshalBinary: %w", err)
	}
	pkHex := hex.EncodeToString(gkBytes)

	s.mu.Lock()
	s.sessions[pkHex] = &pulsarSession{key: mk, gpk: gkBytes}
	s.mu.Unlock()

	// Shares carries one party-index per committee member (0..n-1) — the
	// no-reconstruct hyperball signer addresses parties by these indices.
	shareIDs := make([]string, n)
	for i := 0; i < n; i++ {
		shareIDs[i] = fmt.Sprintf("%d", i)
	}
	return keygenResult{PublicKey: pkHex, Shares: shareIDs}, nil
}

// hyperballSign drives the NO-RECONSTRUCT t-of-n threshold sign for the
// session identified by pubKeyHex and returns ONE FIPS 204 ML-DSA-65
// signature bound to ctx (ctx=nil ⇒ empty-context signature).
//
// It is the single code path behind both Sign (ctx=nil) and the ctx-bound
// Sign_Ctx family: pulsar.MithrilKey.SignHyperball runs the Mithril
// 3-round hyperball protocol across the canonical t-party quorum. No party
// or coordinator ever reconstructs the master ML-DSA key (see the file
// header). SignHyperball uses fresh per-round entropy from rand.Reader, so
// distinct calls under the same group key sign with distinct nonces.
func (s *pulsarScheme) hyperballSign(pubKeyHex string, msg, ctx []byte) (*pulsar.Signature, *pulsar.Params, *pulsar.PublicKey, error) {
	s.mu.Lock()
	sess, ok := s.sessions[pubKeyHex]
	s.mu.Unlock()
	if !ok {
		return nil, nil, nil, fmt.Errorf("unknown pubKeyHex (keygen first)")
	}
	mk := sess.key

	params, err := pulsar.ParamsFor(mk.Mode)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("params: %w", err)
	}

	// Canonical signing quorum: the first t parties {0,…,t−1}. SignHyperball
	// requires a sorted, duplicate-free t-subset of [0,n); the first t is
	// deterministic and any viable t-subset signs identically.
	active := make([]int, mk.T)
	for i := range active {
		active[i] = i
	}

	// NO-RECONSTRUCT signing. Each active party holds only its balanced-
	// partition share s1_(j) and emits only z_j = y_j + c·s1_(j); the
	// coordinator forms only the PUBLIC aggregates. SignHyperball
	// fail-closed self-verifies the summed result under the FIPS 204
	// verifier before returning.
	sig, _, err := mk.SignHyperball(active, msg, ctx, rand.Reader, pulsarHyperballMaxRounds)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("SignHyperball: %w", err)
	}

	gpkPub := &pulsar.PublicKey{Mode: mk.Mode, Bytes: mk.Pub()}
	return sig, params, gpkPub, nil
}

// Sign drives the dealerless-keygen no-reconstruct threshold protocol
// (empty ctx) for the canonical quorum and returns the PULS-framed
// signature wire bytes. The output is bit-identical to a single-party
// FIPS 204 ML-DSA-65 signature on (message, group public key) under the
// empty context — any caller holding the corresponding PULG-framed group
// public key verifies via VerifyBytes (or pulsar.Verify).
func (s *pulsarScheme) Sign(p signParams) (signResult, error) {
	msg, err := hex.DecodeString(p.MessageHex)
	if err != nil {
		return signResult{}, fmt.Errorf("messageHex: %w", err)
	}

	sig, params, groupPK, err := s.hyperballSign(p.PubKeyHex, msg, nil)
	if err != nil {
		return signResult{}, fmt.Errorf("pulsar sign: %w", err)
	}

	// Self-verify safety belt before publishing — refuses to return bytes
	// that would fail at the caller (a failure here is a kernel bug, not a
	// caller bug). SignHyperball already self-verifies internally; this is
	// belt-and-suspenders at the dispatcher boundary.
	if err := pulsar.Verify(params, groupPK, msg, sig); err != nil {
		return signResult{}, fmt.Errorf("pulsar sign: produced signature failed self-verify (kernel bug): %w", err)
	}

	sigBytes, err := sig.MarshalBinary()
	if err != nil {
		return signResult{}, fmt.Errorf("pulsar sign: sig.MarshalBinary: %w", err)
	}
	return signResult{SignatureHex: hex.EncodeToString(sigBytes)}, nil
}

// Sign_Ctx is the ctx-bound signing surface for the pulsar dispatcher. It
// emits a FIPS 204 §5.2 context-bound ML-DSA-65 signature on (msg, ctx)
// under the session's group public key, so callers can produce signatures
// that satisfy the on-chain EVM precompile's domain-separation contract:
//
//	`lux-evm-precompile-mldsa-v1`   → luxfi/precompile/mldsa
//	(pub.VerifySignatureCtx(msg, sig, ctx))
//
// Wire bytes: PULS-framed (Signature.MarshalBinary) — bit-identical to a
// single-party FIPS 204 §5.2 ctx-bound signature on the same (group key,
// msg, ctx) tuple. Any FIPS 204 verifier holding the session's PULG-framed
// group public key bytes accepts the result under VerifyCtx(pub, msg, ctx,
// sig).
//
// NOTE on strict-PQ: this is the legacy entry point and does NOT consult
// the strict-PQ profile gate. The dispatcher always routes ctx-bound signs
// through Sign_Ctx_Profile (which runs the gate); in-process embedders with
// their own admission gate may call this directly. signCtx is the FIPS 204
// ctx octet string (0..255 bytes); pass "" to bind the empty ctx
// (byte-identical to Sign).
func (s *pulsarScheme) Sign_Ctx(p signCtxParams) (signResult, error) {
	return s.signCtxInternal(p)
}

// Sign_Ctx_Profile is the profile-aware entry point. The dispatcher always
// routes here (pulsar implements profileAwareCtxSigner — see types.go). The
// strict-PQ gate fires at entry: on a strict-PQ chain the call is refused
// with ErrRefusedUnderStrictPQ; on any other profile, or with no resolver
// wired, it falls through to signCtxInternal.
//
// ----------------------------------------------------------------------
// Why the strict-PQ gate STILL refuses pulsar (reasoned, not reflexive).
// ----------------------------------------------------------------------
//
// The signing path is now genuinely no-reconstruct: SignHyperball forms
// NO master ML-DSA secret key anywhere (each party emits only z_j; the
// coordinator sums public partials). So the gate's ORIGINAL rationale —
// "LargeCombine transiently reconstructs the master sk" — no longer
// applies; that reconstruct-at-combine path is gone.
//
// But the gate is NOT a no-op, and silently dropping it would delete real
// safety. This dispatcher is an IN-PROCESS dev-tooling combiner: the
// dealerless RSS keygen produces ONE MithrilKey that holds EVERY party's
// subset secrets co-resident in a single process (mk.holdings covers all
// n parties). No-reconstruct protects the SIGNING transcript, but it does
// not change the fact that the full secret material is materialisable here
// by an operator of this process (e.g. via the reconstruct-style
// MithrilKey.Sign, which this dispatcher deliberately does NOT call). A
// strict-PQ chain — the highest-assurance tier — must source its ctx-bound,
// precompile-acceptable finality signatures from a GENUINELY DISTRIBUTED
// ceremony where each validator holds only its own subset holdings in
// separate HSM / KMS and the no-reconstruct property is a true network
// invariant, NOT from this in-process dispatcher where all holdings
// co-reside. The gate is the deployment boundary that enforces that
// separation, so it stays. (For the dispatcher's own in-process model the
// distinction is moot — all holdings already co-reside — which is exactly
// why the dispatcher is dev tooling and not a strict-PQ finality source.)
//
// One function, one place: profile.go owns the policy
// (RefuseUnderStrictPQ); this method owns the call site. Non-strict and
// no-resolver deployments fall straight through to the real dealerless
// no-reconstruct threshold sign.
func (s *pulsarScheme) Sign_Ctx_Profile(p signCtxParams, resolver ChainProfileResolver) (signResult, error) {
	if err := RefuseUnderStrictPQ(p.ChainID, "pulsar.sign_ctx", resolver); err != nil {
		return signResult{}, err
	}
	return s.signCtxInternal(p)
}

// signCtxInternal is the ctx-bound dealerless no-reconstruct path. It
// decodes the ctx octet string and drives the single hyperballSign helper;
// the empty ctx case (CtxHex == "") is byte-identical to Sign(msg).
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

	sig, params, groupPK, err := s.hyperballSign(p.PubKeyHex, msg, signCtx)
	if err != nil {
		return signResult{}, fmt.Errorf("pulsar sign_ctx: %w", err)
	}

	// Self-verify safety belt — refuses to publish bytes that would fail
	// at the caller. Uses VerifyCtx so ctx binding is covered.
	if err := pulsar.VerifyCtx(params, groupPK, msg, signCtx, sig); err != nil {
		return signResult{}, fmt.Errorf("pulsar sign_ctx: produced signature failed self-verify (kernel bug): %w", err)
	}

	sigBytes, err := sig.MarshalBinary()
	if err != nil {
		return signResult{}, fmt.Errorf("pulsar sign_ctx: sig.MarshalBinary: %w", err)
	}
	return signResult{SignatureHex: hex.EncodeToString(sigBytes)}, nil
}

// Verify is stateless: it decodes the supplied PULG-framed group public
// key + PULS-framed signature wire bytes and runs the pulsar kernel's
// stateless VerifyBytes (raw FIPS 204 ML-DSA-65 under the empty ctx).
//
// The dispatcher does NOT consult any in-process session — the supplied
// PubKeyHex IS the authority. This is the contract that independent peers
// (other mpcd, bridge nodes, L1 verifier contracts) must satisfy.
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
