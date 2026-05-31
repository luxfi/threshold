// SPDX-License-Identifier: BSD-3-Clause
package thresholdd

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	magnetar "github.com/luxfi/magnetar/ref/go/pkg/magnetar"
)

// magnetarScheme wires luxfi/magnetar (FIPS 205 SLH-DSA, hash-based
// post-quantum signature) into the JSON-RPC surface.
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
//   - The PRIMARY per-validator standalone path is the JSON-RPC
//     surface. Keygen generates `participants` independent SLH-DSA
//     keypairs; the dispatcher retains them all keyed by the FIRST
//     validator's MAGG-framed public-key hex; Sign returns the FIRST
//     validator's MAGS-framed signature.
//   - The wire bytes are byte-identical to single-party FIPS 205 on
//     the (msg, pk_0) pair — verifiable by any external party with
//     a FIPS 205 verifier and the documented MAGG / MAGS frame.
//   - The N-of-N collected-signatures form (ValidatorAggregateCert)
//     is not on the JSON-RPC surface today because the bus shape
//     (one signatureHex per .sign call) doesn't naturally carry N
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
}

// magnetarSession holds the in-process per-validator keypairs for
// one Keygen output. The canonical PublicKey for the session is the
// MAGG-framed wire bytes of `keys[0].pk`; subsequent Sign calls
// reference this session via PubKeyHex.
type magnetarSession struct {
	mode magnetar.Mode

	// keys are the N per-validator keypairs. Index 0 is the
	// canonical signer (the one whose pk is published as the
	// session's PublicKey on the JSON-RPC surface). Indices 1..N-1
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
func (s *magnetarScheme) Sign(p signParams) (signResult, error) {
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
