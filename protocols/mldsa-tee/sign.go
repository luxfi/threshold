// SPDX-License-Identifier: BSD-3-Clause

package mldsatee

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	pulsar "github.com/luxfi/pulsar/ref/go/pkg/pulsar"

	"github.com/luxfi/mpc/pkg/approval"
)

// Sign produces a FIPS 204 ML-DSA signature on msg, gated by the
// supplied attestation Envelope. Same flow as slhdsa-tee.Signer.Sign;
// differs only in the inner primitive (pulsar instead of magnetar).
//
// Output is the PULS-framed wire bytes (via Signature.MarshalBinary)
// — byte-identical to single-party FIPS 204 SignDeterministic on the
// same (seed-derived sk, msg, ctx).
func (s *Signer) Sign(ctx context.Context, env *Envelope, jobID [32]byte, msg []byte, signCtx []byte) ([]byte, *SignReceipt, error) {
	if env == nil {
		return nil, nil, ErrAttestationRequired
	}
	if len(msg) == 0 {
		return nil, nil, fmt.Errorf("mldsa-tee: empty message")
	}

	sealed, err := s.auditedRelease(ctx, env, jobID, msg)
	if err != nil {
		return nil, nil, err
	}

	raw, err := s.hsmP.GetKey(ctx, s.cfg.WrappedSeedKeyID)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: HSM GetKey: %v", ErrHSMUnreachable, err)
	}
	defer zeroize(raw)

	if len(raw) != pulsar.SeedSize {
		return nil, nil, fmt.Errorf("%w: HSM-stored seed length %d does not match pulsar.SeedSize %d",
			ErrCorruptWrappedSeed, len(raw), pulsar.SeedSize)
	}
	var seed [pulsar.SeedSize]byte
	copy(seed[:], raw)
	defer zeroizeArr(&seed)

	sk, err := pulsar.KeyFromSeed(s.params, seed)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: KeyFromSeed: %v", ErrCorruptWrappedSeed, err)
	}
	defer zeroize(sk.Bytes)
	defer zeroizeArr(&sk.Seed)

	sig, err := pulsar.Sign(s.params, sk, msg, signCtx, false /*deterministic*/, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("mldsa-tee: pulsar.Sign: %w", err)
	}

	// Self-verify safety belt.
	if err := pulsar.Verify(s.params, sk.Pub, msg, sig); err != nil {
		return nil, nil, fmt.Errorf("mldsa-tee: self-verify failed (kernel bug): %w", err)
	}

	wire, err := sig.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("mldsa-tee: sig.MarshalBinary: %w", err)
	}

	audit, err := s.auditSignature(ctx, jobID, msg, sealed.Epoch, env.RIM)
	if err != nil {
		return nil, nil, fmt.Errorf("mldsa-tee: audit signature: %w", err)
	}

	recv := &SignReceipt{
		JobID:          jobID,
		Epoch:          sealed.Epoch,
		IssuedNonce:    sealed.IssuedNonce,
		EphemeralPub:   sealed.EphemeralPub,
		EvidenceKind:   string(env.Kind),
		EvidenceIssuer: evidenceIssuerString(env),
		AuditSignature: audit,
	}
	return wire, recv, nil
}

// SignReceipt is the audit blob returned alongside the FIPS 204
// signature.
type SignReceipt struct {
	JobID          [32]byte
	Epoch          uint64
	IssuedNonce    [32]byte
	EphemeralPub   [32]byte
	EvidenceKind   string
	EvidenceIssuer string
	AuditSignature []byte
}

func (s *Signer) auditSignature(ctx context.Context, jobID [32]byte, msg []byte, epoch uint64, rim [32]byte) ([]byte, error) {
	h := sha256.New()
	h.Write([]byte("LUX-MLDSA-TEE-AUDIT-V1"))
	h.Write([]byte{0x00})
	h.Write(jobID[:])
	h.Write(epochBytes(epoch))
	h.Write(rim[:])
	d := sha256.Sum256(msg)
	h.Write(d[:])
	auditDigest := h.Sum(nil)
	return s.hsmP.Sign(ctx, s.cfg.KMSKeyID, auditDigest)
}

func epochBytes(e uint64) []byte {
	return []byte{
		byte(e >> 56), byte(e >> 48), byte(e >> 40), byte(e >> 32),
		byte(e >> 24), byte(e >> 16), byte(e >> 8), byte(e),
	}
}

func evidenceIssuerString(env *Envelope) string {
	switch is := env.EvidenceIssuers(); len(is) {
	case 0:
		return ""
	default:
		return is[0]
	}
}

// signIntent satisfies approval.CanonicalIntent for the (jobID, msg,
// envelope-summary) tuple.
type signIntent struct {
	jobID [32]byte
	msg   []byte
	env   envelopeSummary
}

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
	h.Write([]byte("LUX-MLDSA-TEE-INTENT-V1"))
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

// Bytes implements approval.CanonicalIntent.
func (si *signIntent) Bytes() []byte {
	out := make([]byte, 0, 32+32+len(si.env.Kind)+1+32+32+32+32)
	out = append(out, []byte("LUX-MLDSA-TEE-INTENT-V1")...)
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

// FreshJobID returns 32 bytes of crypto/rand.
func FreshJobID() ([32]byte, error) {
	var out [32]byte
	if _, err := rand.Read(out[:]); err != nil {
		return out, err
	}
	return out, nil
}
