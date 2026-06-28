// SPDX-License-Identifier: BSD-3-Clause
package thresholdd

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"

	pulsar "github.com/luxfi/pulsar/ref/go/pkg/pulsar"
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
// pinned upstream by TestPrecompile_E2E_LargeCombine_FIPS204_VerifyCtx
// and TestLarge_E2E_DKG_ThresholdSign_Verify.
//
// ----------------------------------------------------------------------
// Trust model on KEYGEN — DEALERLESS committee DKG (pulsar v1.2.0).
// ----------------------------------------------------------------------
//
//   - The dispatcher runs the GF(q) wide-committee distributed key
//     generation (pulsar.NewLargeDKGSession → Round1/Round2/Round3).
//     There is NO trusted dealer. Each of the n parties samples its own
//     secret contribution c_i, GF(q)-Shamir-shares it to every committee
//     member inside an ML-KEM-768-sealed per-recipient envelope, and the
//     master ML-DSA seed emerges as Σ_i c_i. NO single party ever holds
//     the master seed at any point during keygen: each party learns only
//     its own aggregate Shamir share f(x_i) = Σ_i f_i(x_i) and the public
//     group key. This is the owner's-law path: "remove trusted-dealer,
//     not allowed" — the prior v0.3 pulsar.DealAlgebraicV03Shares dealer
//     is GONE. The same dealerless DKG is what a permissioned-consortium
//     / audit-attestation deployment runs; consensus chain-genesis uses
//     the same primitive driven across the messaging bus instead of
//     in-process.
//
// ----------------------------------------------------------------------
// Trust model on SIGN — t-of-n threshold, reconstruct-at-combine.
// ----------------------------------------------------------------------
//
//   - The 2-round protocol (NewLargeThresholdSigner → Round1 → Round2)
//     runs in-process across the t signers in the quorum, then
//     pulsar.LargeCombine aggregates the t Round-2 reveals into ONE
//     FIPS 204 ML-DSA-65 signature. A single party CANNOT produce the
//     signature alone — t valid Round-2 reveals are required, so the
//     threshold guarantee is genuine.
//
//   - HONEST CRYPTOGRAPHIC NOTE (load-bearing for the strict-PQ gate
//     below): LargeCombine is a RECONSTRUCT-style combiner. It Lagrange-
//     interpolates the t revealed GF(q) shares to recover the master
//     seed, derives the full ML-DSA secret key (KeyFromSeed), signs with
//     it, and immediately zeroizes it. So unlike the no-reconstruct
//     TALUS BCC/CEF distributed signer (which never materialises the
//     master sk anywhere), this path TRANSIENTLY materialises the master
//     secret key in the combiner's memory at every sign. For the
//     in-process dispatcher — where all n shares already co-reside in one
//     process and the role is off-chain dev tooling / MPC-bus integration
//     tests / SDK-driven harnesses, NOT chain-genesis finality — this
//     changes nothing: the master key is reconstructible here regardless
//     of which combiner is used. It DOES matter for a real distributed
//     deployment, which is exactly why the strict-PQ gate refuses this
//     path (see Sign_Ctx_Profile).
//
//   - One ctx-aware path. The plain Sign (empty ctx) and the ctx-bound
//     Sign_Ctx collapse into a single largeSign helper that threads the
//     FIPS 204 §5.2 ctx octet string into LargeCombine; ctx=nil yields
//     the empty-context signature. The dispatcher returns the PULS-framed
//     wire bytes; callers MUST verify via VerifyBytes (or pulsar.VerifyCtx)
//     using ONLY the published PULG-framed group public key.
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

// pulsarSession holds the in-process per-party state produced by one
// dealerless committee-DKG keygen, keyed in the scheme by the PULG-framed
// group public key hex.
type pulsarSession struct {
	threshold int

	// groupPK is the dealerless-derived FIPS 204 ML-DSA-65 group public
	// key. Every committee member's DKG output agrees on this value.
	groupPK *pulsar.PublicKey

	// committee is the canonical byte-ascending NodeID committee (matches
	// pulsar's internal canonicalisation). The signing quorum is the
	// first `threshold` entries.
	committee []pulsar.NodeID

	// shareByID maps each committee member's NodeID to its GF(q) aggregate
	// Shamir key share (the dealerless DKG output). The dispatcher retains
	// these in-process; raw share material never crosses the wire.
	shareByID map[pulsar.NodeID]*pulsar.LargeKeyShare

	// allShares is every committee member's share, in canonical committee
	// order. LargeCombine consumes the full slice for its NodeID→eval-point
	// mapping (it reads only the eval points, never the secret lanes).
	allShares []*pulsar.LargeKeyShare

	// identities holds each committee member's long-term ML-KEM-768 +
	// ML-DSA-65 identity. In production each party holds its own keypair
	// in HSM / KMS; in the in-process dispatcher they all live here so the
	// per-pair authenticated session-key establishment can run locally.
	identities map[pulsar.NodeID]*pulsar.IdentityKey

	// sessionCounter increments per Sign call so distinct messages signed
	// under the same group key use distinct sessionIDs (pulsar's
	// per-signature freshness contract). Bumped inside the scheme mutex.
	sessionCounter uint64
}

// sessionID call-site tags (trailing 8 bytes of the 16-byte sessionID).
// The leading 8 bytes carry the per-session freshness counter; these tags
// only make a captured wire trace unambiguously attributable to the plain
// Sign vs the ctx-bound Sign_Ctx call site.
const (
	pulsarTagSignPlain uint64 = 0xDEADBEEFCAFEBABE
	pulsarTagSignCtx   uint64 = 0xC1C1BAB1ECAFE505
)

func newPulsarScheme() *pulsarScheme {
	return &pulsarScheme{sessions: make(map[string]*pulsarSession)}
}

// Keygen runs the DEALERLESS GF(q) committee DKG
// (pulsar.NewLargeDKGSession → Round1/Round2/Round3) for t-of-n,
// publishes the canonical PULG-framed group public key bytes as
// PublicKey, and returns one decimal eval-point per party in Shares.
//
// NO trusted dealer: every party samples and Shamir-shares its own
// contribution; no single party ever holds the master ML-DSA seed during
// the ceremony. The dispatcher retains the per-party aggregate Shamir
// shares in-process keyed by the PublicKey hex; subsequent Sign calls
// reference the session via PubKeyHex. Raw share material never crosses
// the wire — the Shares slice carries only eval-point indices.
func (s *pulsarScheme) Keygen(p keygenParams) (keygenResult, error) {
	if err := validateKeygenParams(p); err != nil {
		return keygenResult{}, err
	}

	params := pulsar.MustParamsFor(pulsar.ModeP65)

	// Build a committee of n distinct NodeIDs from a fresh session salt,
	// then canonicalise (byte-ascending) so the dispatcher's positional
	// view matches pulsar's internal committee canonicalisation and the
	// signing quorum is deterministic. Distinct salts across keygens stop
	// concurrent sessions from aliasing.
	var sessionSalt [32]byte
	if _, err := rand.Read(sessionSalt[:]); err != nil {
		return keygenResult{}, fmt.Errorf("pulsar keygen: salt entropy: %w", err)
	}
	committee := make([]pulsar.NodeID, p.Participants)
	for i := 0; i < p.Participants; i++ {
		var idBuf [4]byte
		binary.BigEndian.PutUint32(idBuf[:], uint32(i+1)) // 1-indexed
		seed := sha256.Sum256(append(append([]byte{}, sessionSalt[:]...), idBuf[:]...))
		committee[i] = pulsar.NodeID(seed)
	}
	sort.Slice(committee, func(i, j int) bool {
		return bytes.Compare(committee[i][:], committee[j][:]) < 0
	})

	// Per-party long-term identities (ML-KEM-768 + ML-DSA-65) + directory.
	// The DKG seals per-recipient envelopes under each recipient's KEM
	// public key, so the directory must cover every committee member.
	identities := make(map[pulsar.NodeID]*pulsar.IdentityKey, len(committee))
	pubs := make(map[pulsar.NodeID]*pulsar.IdentityPublicKey, len(committee))
	for _, id := range committee {
		ident, err := pulsar.GenerateIdentity(rand.Reader)
		if err != nil {
			return keygenResult{}, fmt.Errorf("pulsar keygen: GenerateIdentity: %w", err)
		}
		identities[id] = ident
		pubs[id] = ident.PublicKey()
	}
	directory, err := pulsar.NewIdentityDirectory(pubs)
	if err != nil {
		return keygenResult{}, fmt.Errorf("pulsar keygen: NewIdentityDirectory: %w", err)
	}

	// ---- DEALERLESS committee DKG: 3 rounds across all n parties. ----
	sessions := make([]*pulsar.LargeDKGSession, len(committee))
	for i, id := range committee {
		ds, err := pulsar.NewLargeDKGSession(params, committee, p.Threshold, id, identities[id], directory, rand.Reader)
		if err != nil {
			return keygenResult{}, fmt.Errorf("pulsar keygen: NewLargeDKGSession[%d]: %w", i, err)
		}
		sessions[i] = ds
	}
	r1 := make([]*pulsar.LargeDKGRound1Msg, len(sessions))
	for i, ds := range sessions {
		m, err := ds.Round1()
		if err != nil {
			return keygenResult{}, fmt.Errorf("pulsar keygen: DKG Round1[%d]: %w", i, err)
		}
		r1[i] = m
	}
	r2 := make([]*pulsar.LargeDKGRound2Msg, len(sessions))
	for i, ds := range sessions {
		m, err := ds.Round2(r1)
		if err != nil {
			return keygenResult{}, fmt.Errorf("pulsar keygen: DKG Round2[%d]: %w", i, err)
		}
		r2[i] = m
	}
	outs := make([]*pulsar.LargeDKGOutput, len(sessions))
	for i, ds := range sessions {
		out, err := ds.Round3(r1, r2)
		if err != nil {
			return keygenResult{}, fmt.Errorf("pulsar keygen: DKG Round3[%d]: %w", i, err)
		}
		if out.AbortEvidence != nil {
			return keygenResult{}, fmt.Errorf("pulsar keygen: DKG aborted at party %d: %v (accuser=%x accused=%x)",
				i, out.AbortEvidence.Kind, out.AbortEvidence.Accuser[:4], out.AbortEvidence.Accused[:4])
		}
		outs[i] = out
	}

	groupPK := outs[0].GroupPubkey
	if groupPK == nil {
		return keygenResult{}, fmt.Errorf("pulsar keygen: DKG produced nil group public key")
	}
	// Consistency: every party MUST derive the same group public key. A
	// divergence is a DKG soundness failure, not a caller error.
	shareByID := make(map[pulsar.NodeID]*pulsar.LargeKeyShare, len(outs))
	allShares := make([]*pulsar.LargeKeyShare, len(outs))
	for i, out := range outs {
		if out.GroupPubkey == nil || !out.GroupPubkey.Equal(groupPK) {
			return keygenResult{}, fmt.Errorf("pulsar keygen: party %d derived a divergent group key (DKG inconsistency)", i)
		}
		if out.SecretShare == nil {
			return keygenResult{}, fmt.Errorf("pulsar keygen: party %d produced nil secret share", i)
		}
		shareByID[out.SecretShare.NodeID] = out.SecretShare
		allShares[i] = out.SecretShare
	}

	gkBytes, err := groupPK.MarshalBinary()
	if err != nil {
		return keygenResult{}, fmt.Errorf("pulsar keygen: groupPK.MarshalBinary: %w", err)
	}
	pkHex := hex.EncodeToString(gkBytes)

	s.mu.Lock()
	s.sessions[pkHex] = &pulsarSession{
		threshold:  p.Threshold,
		groupPK:    groupPK,
		committee:  committee,
		shareByID:  shareByID,
		allShares:  allShares,
		identities: identities,
	}
	s.mu.Unlock()

	shareIDs := make([]string, len(allShares))
	for i := range allShares {
		shareIDs[i] = fmt.Sprintf("%d", allShares[i].EvalPoint)
	}
	return keygenResult{PublicKey: pkHex, Shares: shareIDs}, nil
}

// largeSign drives the dealerless-keygen t-of-n threshold sign for the
// session identified by pubKeyHex and returns ONE FIPS 204 ML-DSA-65
// signature bound to ctx (ctx=nil ⇒ empty-context signature).
//
// It is the single code path behind both Sign (ctx=nil) and the ctx-bound
// Sign_Ctx family: NewLargeThresholdSigner → Round1 → Round2 →
// LargeCombine, with the t-quorum's per-pair session keys established via
// authenticated ML-KEM-768 key agreement (pulsar.SymmetricSession).
//
// callTag only tags the sessionID trailing bytes for wire-trace
// attribution; freshness comes from the per-session counter.
func (s *pulsarScheme) largeSign(pubKeyHex string, msg, ctx []byte, callTag uint64) (*pulsar.Signature, *pulsar.Params, *pulsar.PublicKey, error) {
	s.mu.Lock()
	sess, ok := s.sessions[pubKeyHex]
	if !ok {
		s.mu.Unlock()
		return nil, nil, nil, fmt.Errorf("unknown pubKeyHex (keygen first)")
	}
	sess.sessionCounter++
	counter := sess.sessionCounter
	threshold := sess.threshold
	groupPK := sess.groupPK
	committee := append([]pulsar.NodeID(nil), sess.committee...)
	shareByID := sess.shareByID
	allShares := append([]*pulsar.LargeKeyShare(nil), sess.allShares...)
	identities := sess.identities
	s.mu.Unlock()

	if threshold <= 0 || threshold > len(committee) {
		return nil, nil, nil, fmt.Errorf("session has invalid threshold %d for committee %d", threshold, len(committee))
	}
	params := pulsar.MustParamsFor(groupPK.Mode)

	// Canonical quorum: the first t committee members (committee is already
	// byte-ascending). Any t-subset reconstructs; the first t is
	// deterministic.
	quorum := append([]pulsar.NodeID(nil), committee[:threshold]...)

	// Distinct sessionID per Sign call (freshness across concurrent signs
	// under the same group key). Trailing 8 bytes tag the call site.
	var sid [16]byte
	binary.BigEndian.PutUint64(sid[:8], counter)
	binary.BigEndian.PutUint64(sid[8:], callTag)
	attempt := uint32(0)

	// Per-pair authenticated session keys for the quorum (ML-KEM-768
	// encapsulation + ML-DSA-65 authentication). Bound to (sid, msg); ctx
	// enters later, at LargeCombine's μ derivation.
	sessionKeys, err := pulsarQuorumSessionKeys(quorum, identities, sid, msg)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("session keys: %w", err)
	}

	// Build the t threshold signers.
	signers := make([]*pulsar.LargeThresholdSigner, threshold)
	for i, id := range quorum {
		share, ok := shareByID[id]
		if !ok {
			return nil, nil, nil, fmt.Errorf("missing key share for quorum member %x", id[:4])
		}
		ts, err := pulsar.NewLargeThresholdSigner(params, sid, attempt, quorum, share, sessionKeys[id], msg, rand.Reader)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("NewLargeThresholdSigner[%d]: %w", i, err)
		}
		signers[i] = ts
	}

	// Round 1: commit broadcasts.
	tsR1 := make([]*pulsar.LargeRound1Message, threshold)
	for i, ts := range signers {
		m, err := ts.Round1(msg)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("sign Round1[%d]: %w", i, err)
		}
		tsR1[i] = m
	}

	// Round 2: MAC-checked (mask, masked-share) reveals.
	tsR2 := make([]*pulsar.LargeRound2Message, threshold)
	for i, ts := range signers {
		m, ev, err := ts.Round2(tsR1)
		if err != nil {
			if ev != nil {
				return nil, nil, nil, fmt.Errorf("sign Round2[%d]: %w (abort: %v accused=%x)", i, err, ev.Kind, ev.Accused[:4])
			}
			return nil, nil, nil, fmt.Errorf("sign Round2[%d]: %w", i, err)
		}
		tsR2[i] = m
	}

	// Combine the t reveals into one FIPS 204 ML-DSA-65 signature bound
	// to ctx (ctx=nil ⇒ empty context). randomized=false ⇒ deterministic
	// FIPS 204 hedged-but-derandomised path.
	sig, err := pulsar.LargeCombine(params, groupPK, msg, ctx, false, sid, attempt, quorum, threshold, tsR1, tsR2, allShares)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("LargeCombine: %w", err)
	}
	return sig, params, groupPK, nil
}

// Sign drives the dealerless-keygen threshold protocol (empty ctx) for the
// quorum in the session and returns the PULS-framed signature wire bytes.
// The output is bit-identical to a single-party FIPS 204 ML-DSA-65
// signature on (message, group public key) under the empty context — any
// caller holding the corresponding PULG-framed group public key verifies
// via VerifyBytes (or pulsar.Verify).
func (s *pulsarScheme) Sign(p signParams) (signResult, error) {
	msg, err := hex.DecodeString(p.MessageHex)
	if err != nil {
		return signResult{}, fmt.Errorf("messageHex: %w", err)
	}

	sig, params, groupPK, err := s.largeSign(p.PubKeyHex, msg, nil, pulsarTagSignPlain)
	if err != nil {
		return signResult{}, fmt.Errorf("pulsar sign: %w", err)
	}

	// Self-verify safety belt before publishing — refuses to return bytes
	// that would fail at the caller (a failure here is a kernel bug, not a
	// caller bug).
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
// single-party FIPS 204 §5.2 ctx-bound signature on the same (master_sk,
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
// The gate originally guarded the pulsar v1.0.x single-party DEALER
// shortcut (a real single-party PrivateKey lived in pulsarSession, so
// "threshold" was a lie). That shortcut is GONE: keygen is now the
// dealerless committee DKG (NewLargeDKGSession) and sign is a genuine
// t-of-n LargeCombine — one party cannot sign alone. So the SPECIFIC
// thing the gate first named no longer exists.
//
// But the gate is NOT a no-op for this path, and silently dropping it
// would delete real safety. The v1.2.0 LargeCombine is a RECONSTRUCT-style
// combiner: it Lagrange-interpolates the master seed, derives the full
// ML-DSA secret key, signs, and wipes it — TRANSIENTLY materialising the
// master sk in one party's memory at every sign. That is strictly weaker
// than the no-reconstruct TALUS BCC/CEF distributed signer (which never
// forms the master sk anywhere). A strict-PQ chain — the highest-assurance
// tier — must source its ctx-bound, precompile-acceptable finality
// signatures from the consensus-driven distributed no-reconstruct
// ceremony, NOT from this in-process dev-tooling dispatcher whose combiner
// reconstructs the key. The gate is the policy boundary that enforces that
// separation, so it stays. (For the dispatcher's own in-process model the
// reconstruct is moot — all shares already co-reside — which is precisely
// why the dispatcher is dev tooling and not a strict-PQ finality source.)
//
// One function, one place: profile.go owns the policy
// (RefuseUnderStrictPQ); this method owns the call site. Non-strict and
// no-resolver deployments fall straight through to the real dealerless
// threshold sign.
func (s *pulsarScheme) Sign_Ctx_Profile(p signCtxParams, resolver ChainProfileResolver) (signResult, error) {
	if err := RefuseUnderStrictPQ(p.ChainID, "pulsar.sign_ctx", resolver); err != nil {
		return signResult{}, err
	}
	return s.signCtxInternal(p)
}

// signCtxInternal is the ctx-bound dealerless threshold path. It decodes
// the ctx octet string and drives the single largeSign helper; the empty
// ctx case (CtxHex == "") is byte-identical to Sign(msg).
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

	sig, params, groupPK, err := s.largeSign(p.PubKeyHex, msg, signCtx, pulsarTagSignCtx)
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

// pulsarQuorumSessionKeys establishes the per-pair authenticated session
// keys for the quorum, mirroring the upstream test fixture's
// quorumSessionKeys: for every unordered pair {a,b} it runs
// pulsar.SymmetricSession (authenticated ML-KEM-768 key agreement) and
// records the byte-identical key under both parties' views. The returned
// map is keyed [me][peer] → 32-byte session key; NewLargeThresholdSigner
// consumes sessionKeys[me].
//
// In a real distributed deployment each party drives Round 0 of the
// identity KEM exchange over the message bus; the in-process dispatcher
// runs both sides locally because it holds every identity key.
func pulsarQuorumSessionKeys(
	quorum []pulsar.NodeID,
	identities map[pulsar.NodeID]*pulsar.IdentityKey,
	sid [16]byte,
	transcript []byte,
) (map[pulsar.NodeID]map[pulsar.NodeID][32]byte, error) {
	out := make(map[pulsar.NodeID]map[pulsar.NodeID][32]byte, len(quorum))
	for _, id := range quorum {
		out[id] = make(map[pulsar.NodeID][32]byte, len(quorum)-1)
	}
	for i := 0; i < len(quorum); i++ {
		for j := i + 1; j < len(quorum); j++ {
			a, b := quorum[i], quorum[j]
			ka, oka := identities[a]
			kb, okb := identities[b]
			if !oka || !okb {
				return nil, fmt.Errorf("missing identity for session pair %x/%x", a[:4], b[:4])
			}
			key, err := pulsar.SymmetricSession(a, ka, b, kb, sid, transcript)
			if err != nil {
				return nil, fmt.Errorf("SymmetricSession %x<->%x: %w", a[:4], b[:4], err)
			}
			out[a][b] = key
			out[b][a] = key
		}
	}
	return out, nil
}
