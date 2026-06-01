// SPDX-License-Identifier: BSD-3-Clause

package slhdsatee

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	magnetar "github.com/luxfi/magnetar/ref/go/pkg/magnetar"
	"github.com/luxfi/mpc/pkg/approval"
)

// Sign produces a FIPS 205 SLH-DSA signature on msg, gated by the
// supplied attestation Envelope.
//
// Flow (decomplected — each step is independent and complete):
//
//  1. approval.ApproveIntent — out-of-band human/programmatic gate.
//  2. gate.Issue — fresh nonce + epoch from KMS.
//  3. env.Verify(nonce) — operator bound the gate-nonce into
//     REPORT_DATA at TEE capture.
//  4. env.VerifyEvidence(ctx) — cc/attest chain validates the report
//     against vendor root (AMD KDS / TDX PCS / NRAS JWKS).
//  5. gate.Release — gate.RIM ∋ env.RIM, gate.Hardware ∋ env.Hardware,
//     Require* issuers present, seal a session key under env.TEEPub.
//  6. Inside the TEE: unwrap sealed session key, decrypt the wrapped
//     master seed (this package's surface treats hsm.Provider.GetKey
//     as already-yielding-plaintext-inside-attested-TEE; production
//     deployments perform AEAD-unwrap with sealed key here).
//  7. magnetar.KeyFromSeed(seed) → magnetar.Sign(msg, ctx, det=true).
//  8. Zeroize seed + sk.Bytes immediately. Return sig + sealed key
//     metadata so callers can audit (epoch, jobID, ephemeral pub).
//
// Output is the MAGS-framed wire bytes (via Signature.MarshalBinary)
// — byte-identical to single-party FIPS 205 SignDeterministic on
// the same (seed-derived sk, msg). Any verifier with the matching
// magnetar.PublicKey (or its MAGG wire bytes) validates with
// magnetar.Verify / VerifyBytes.
//
// jobID is the audit-binding identifier — opaque to the gate, bound
// into AAD so cross-job replay of the sealed key is refused.
// Production callers derive jobID = sha256(domain || workload || msg)
// or any other collision-free convention. Tests use fresh random.
//
// signCtx is the FIPS 205 §10.2 context string. Pass nil for empty.
//
// Sign is safe for concurrent calls against the same Signer. Each
// call generates an independent jobID-keyed nonce and seals to a
// fresh ephemeral key.
func (s *Signer) Sign(ctx context.Context, env *Envelope, jobID [32]byte, msg []byte, signCtx []byte) ([]byte, *SignReceipt, error) {
	if env == nil {
		return nil, nil, ErrAttestationRequired
	}
	if len(msg) == 0 {
		return nil, nil, fmt.Errorf("slhdsa-tee: empty message")
	}

	sealed, err := s.auditedRelease(ctx, env, jobID, msg)
	if err != nil {
		return nil, nil, err
	}

	// Pull the wrapped master seed from the HSM. Production
	// deployments AEAD-unwrap with the sealed session-key here; for
	// the institutional-custody surface where the HSM itself enforces
	// at-rest confidentiality (AWS KMS, Azure Key Vault, GCP Cloud
	// KMS, Zymbit, YubiHSM, KMS secret manager), GetKey returns the
	// plaintext seed inside the attested TEE context.
	seed, err := s.hsmP.GetKey(ctx, s.cfg.WrappedSeedKeyID)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: HSM GetKey: %v", ErrHSMUnreachable, err)
	}
	defer zeroize(seed)

	if len(seed) != s.params.SeedSize {
		return nil, nil, fmt.Errorf("%w: HSM-stored seed length %d does not match SeedSize %d (mode=%s)",
			ErrCorruptWrappedSeed, len(seed), s.params.SeedSize, s.params.Mode)
	}

	sk, err := magnetar.KeyFromSeed(s.params, seed)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: KeyFromSeed: %v", ErrCorruptWrappedSeed, err)
	}
	defer zeroize(sk.Bytes)
	defer zeroize(sk.Seed)

	sig, err := magnetar.Sign(s.params, sk, msg, signCtx, false /*deterministic*/, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("slhdsa-tee: magnetar.Sign: %w", err)
	}

	// Self-verify safety belt — refuses to return bytes that would
	// fail at the caller. A failure here signals a kernel bug, not a
	// caller bug. Matches the dispatcher's discipline.
	if err := magnetar.VerifyCtx(s.params, sk.Pub, msg, signCtx, sig); err != nil {
		return nil, nil, fmt.Errorf("slhdsa-tee: self-verify failed (kernel bug): %w", err)
	}

	wire, err := sig.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("slhdsa-tee: sig.MarshalBinary: %w", err)
	}

	// Optionally write an HSM-backed audit signature over
	// (jobID, msgDigest, epoch, RIM) — institutional custody
	// auditors replay this against the HSM's KMS audit log to prove
	// the release happened. The signature does not feed back into
	// the FIPS 205 wire bytes; it lives only in the SignReceipt.
	audit, err := s.auditSignature(ctx, jobID, msg, sealed.Epoch, env.RIM)
	if err != nil {
		return nil, nil, fmt.Errorf("slhdsa-tee: audit signature: %w", err)
	}

	recv := &SignReceipt{
		JobID:           jobID,
		Epoch:           sealed.Epoch,
		IssuedNonce:     sealed.IssuedNonce,
		EphemeralPub:    sealed.EphemeralPub,
		EvidenceKind:    string(env.Kind),
		EvidenceIssuer:  evidenceIssuerString(env),
		AuditSignature:  audit,
	}
	return wire, recv, nil
}

// SignReceipt is the audit blob returned alongside the FIPS 205
// signature. Embedders log this to the KMS audit channel; nothing
// in it is cryptographically required for verification — Verify
// only needs (gpkBytes, msg, sigBytes).
type SignReceipt struct {
	JobID          [32]byte
	Epoch          uint64
	IssuedNonce    [32]byte
	EphemeralPub   [32]byte
	EvidenceKind   string
	EvidenceIssuer string
	AuditSignature []byte
}

// auditSignature emits an HSM-backed signature over the canonical
// (jobID || msgDigest || epoch || rim) tuple via the configured HSM
// provider. The HSM's Sign API is provider-native: AWS KMS uses
// ECDSA-P256, Azure Key Vault uses Ed25519 / ECDSA, the file
// provider uses Ed25519. The signature is opaque-bytes from this
// package's perspective — auditors who trust the HSM root validate
// against the provider's pubkey.
func (s *Signer) auditSignature(ctx context.Context, jobID [32]byte, msg []byte, epoch uint64, rim [32]byte) ([]byte, error) {
	h := sha256.New()
	h.Write([]byte("LUX-SLHDSA-TEE-AUDIT-V1"))
	h.Write([]byte{0x00})
	h.Write(jobID[:])
	h.Write(epochBytes(epoch))
	h.Write(rim[:])
	d := sha256.Sum256(msg)
	h.Write(d[:])
	auditDigest := h.Sum(nil)
	return s.hsmP.Sign(ctx, s.cfg.KMSKeyID, auditDigest)
}

// epochBytes encodes epoch as 8 bytes big-endian.
func epochBytes(e uint64) []byte {
	return []byte{
		byte(e >> 56), byte(e >> 48), byte(e >> 40), byte(e >> 32),
		byte(e >> 24), byte(e >> 16), byte(e >> 8), byte(e),
	}
}

// evidenceIssuerString returns the canonical wire issuer for env.
func evidenceIssuerString(env *Envelope) string {
	switch is := env.EvidenceIssuers(); len(is) {
	case 0:
		return ""
	default:
		return is[0]
	}
}

// signIntent satisfies approval.CanonicalIntent for the (jobID, msg,
// envelope-summary) tuple. The approver signs the digest of this
// intent; verification at gate-time re-derives the digest from the
// same inputs and refuses if the approver's signature does not match.
type signIntent struct {
	jobID [32]byte
	msg   []byte
	env   envelopeSummary
}

// envelopeSummary captures the fields of Envelope that participate
// in the approval digest. RIM and Hardware are operator-asserted and
// thus auditable to the approver; the evidence bytes themselves are
// re-captured per Sign and excluded from the intent digest.
type envelopeSummary struct {
	Kind     string
	RIM      [32]byte
	Hardware [32]byte
	TEEPub   [32]byte
}

func newSignIntent(jobID [32]byte, msg []byte, env *Envelope) *signIntent {
	return &signIntent{
		jobID: jobID,
		msg:   append([]byte(nil), msg...),
		env: envelopeSummary{
			Kind:     string(env.Kind),
			RIM:      env.RIM,
			Hardware: env.Hardware,
			TEEPub:   env.TEEPub,
		},
	}
}

// Digest implements approval.CanonicalIntent.
func (si *signIntent) Digest() [32]byte {
	h := sha256.New()
	h.Write([]byte("LUX-SLHDSA-TEE-INTENT-V1"))
	h.Write([]byte{0x00})
	h.Write(si.jobID[:])
	mdigest := sha256.Sum256(si.msg)
	h.Write(mdigest[:])
	h.Write([]byte(si.env.Kind))
	h.Write([]byte{0x00})
	h.Write(si.env.RIM[:])
	h.Write(si.env.Hardware[:])
	h.Write(si.env.TEEPub[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Bytes implements approval.CanonicalIntent. Returns a deterministic
// canonical encoding (no JSON, no length-prefix ambiguity): the same
// fields the Digest hash absorbs, in the same order.
func (si *signIntent) Bytes() []byte {
	out := make([]byte, 0, 32+32+len(si.env.Kind)+1+32+32+32+32)
	out = append(out, []byte("LUX-SLHDSA-TEE-INTENT-V1")...)
	out = append(out, 0x00)
	out = append(out, si.jobID[:]...)
	mdigest := sha256.Sum256(si.msg)
	out = append(out, mdigest[:]...)
	out = append(out, []byte(si.env.Kind)...)
	out = append(out, 0x00)
	out = append(out, si.env.RIM[:]...)
	out = append(out, si.env.Hardware[:]...)
	out = append(out, si.env.TEEPub[:]...)
	return out
}

var _ approval.CanonicalIntent = (*signIntent)(nil)

// FreshJobID returns 32 bytes of crypto/rand. Convenience helper for
// callers that derive jobIDs at random rather than from a domain
// salt; production deployments may prefer a domain-bound jobID.
func FreshJobID() ([32]byte, error) {
	var out [32]byte
	if _, err := rand.Read(out[:]); err != nil {
		return out, err
	}
	return out, nil
}
