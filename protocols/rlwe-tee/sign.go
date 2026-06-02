// SPDX-License-Identifier: BSD-3-Clause

package rlwetee

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	coronaThreshold "github.com/luxfi/corona/threshold"

	"github.com/luxfi/mpc/pkg/approval"
)

// Sign produces a Ring-LWE corona threshold signature on msg, gated
// by the supplied attestation Envelope.
//
// Flow:
//
//  1. approval gate → gate.Issue → env.Verify → env.VerifyEvidence →
//     gate.Release (same as slhdsa-tee / mldsa-tee).
//  2. Inside the TEE: read the wrapped master trusted-dealer key,
//     deterministically regenerate all n key shares + GroupKey via
//     corona.threshold.GenerateKeys, then drive Round1 → Round2 →
//     Finalize across all n parties in-process.
//  3. Zeroize the master key + per-party share state.
//  4. Return the wire-form corona Signature.
//
// Output is a valid corona threshold signature on (gk, msg) that
// any verifier holding the published GroupKey bytes can validate
// via corona.threshold.VerifyBytes.
func (s *Signer) Sign(ctx context.Context, env *Envelope, jobID [32]byte, msg []byte) ([]byte, *SignReceipt, error) {
	if env == nil {
		return nil, nil, ErrAttestationRequired
	}
	if len(msg) == 0 {
		return nil, nil, fmt.Errorf("rlwe-tee: empty message")
	}

	sealed, err := s.auditedRelease(ctx, env, jobID, msg)
	if err != nil {
		return nil, nil, err
	}

	key, err := s.hsmP.GetKey(ctx, s.cfg.WrappedSeedKeyID)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: HSM GetKey: %v", ErrHSMUnreachable, err)
	}
	defer zeroize(key)

	if len(key) != MasterKeySize {
		return nil, nil, fmt.Errorf("%w: HSM-stored key length %d does not match MasterKeySize %d",
			ErrCorruptWrappedSeed, len(key), MasterKeySize)
	}

	// Re-derive every key share + GroupKey deterministically from
	// the master key. corona's GenerateKeys reads sign.KeySize bytes
	// from randSource; bytes.NewReader pins the run reproducibly.
	// The whole GenerateKeys + Round1 + Round2 + Finalize sequence
	// holds coronaSerializer because corona's threshold globals
	// (sign.K, sign.Threshold) and per-party internal state are
	// written by every party in this sequence.
	coronaSerializer.Lock()
	shares, gk, err := coronaThreshold.GenerateKeys(s.cfg.Threshold, s.cfg.Participants, bytes.NewReader(key))
	if err != nil {
		coronaSerializer.Unlock()
		return nil, nil, fmt.Errorf("%w: GenerateKeys: %v", ErrCorruptWrappedSeed, err)
	}

	sigBytes, err := s.runCoronaThresholdSign(jobID, msg, shares, gk)
	coronaSerializer.Unlock()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrCoronaProtocol, err)
	}

	audit, err := s.auditSignature(ctx, jobID, msg, sealed.Epoch, env.RIM)
	if err != nil {
		return nil, nil, fmt.Errorf("rlwe-tee: audit signature: %w", err)
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
	return sigBytes, recv, nil
}

// runCoronaThresholdSign drives Round1 → Round2 → Finalize for all
// n signers in-process. The canonical signer set is [0..n) — corona
// requires distinct integer indices and we honour that. The PRF key
// is sha256(GroupKey bytes || jobID) so distinct sign calls bind
// distinct sessions.
func (s *Signer) runCoronaThresholdSign(jobID [32]byte, msg []byte, shares []*coronaThreshold.KeyShare, gk *coronaThreshold.GroupKey) ([]byte, error) {
	n := len(shares)
	signerIDs := make([]int, n)
	for i := range signerIDs {
		signerIDs[i] = i
	}

	gkBytes, err := gk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("gk.MarshalBinary: %w", err)
	}
	prfDigest := sha256.New()
	prfDigest.Write(gkBytes)
	prfDigest.Write(jobID[:])
	prfKey := prfDigest.Sum(nil)

	sessionID := sessionIDFromJobID(jobID)

	signers := make([]*coronaThreshold.Signer, n)
	for i := 0; i < n; i++ {
		signers[i] = coronaThreshold.NewSigner(shares[i])
	}

	r1Data := make(map[int]*coronaThreshold.Round1Data, n)
	for _, signer := range signers {
		r1 := signer.Round1(sessionID, prfKey, signerIDs)
		r1Data[r1.PartyID] = r1
	}

	msgStr := string(msg)
	r2Data := make(map[int]*coronaThreshold.Round2Data, n)
	for _, signer := range signers {
		r2, err := signer.Round2(sessionID, msgStr, prfKey, signerIDs, r1Data)
		if err != nil {
			return nil, fmt.Errorf("round2: %w", err)
		}
		r2Data[r2.PartyID] = r2
	}

	sig, err := signers[0].Finalize(r2Data)
	if err != nil {
		return nil, fmt.Errorf("finalize: %w", err)
	}

	if !coronaThreshold.Verify(gk, msgStr, sig) {
		return nil, fmt.Errorf("self-verify failed (kernel bug)")
	}

	wire, err := sig.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("sig.MarshalBinary: %w", err)
	}
	return wire, nil
}

// SignReceipt is the audit blob returned alongside the corona
// threshold signature.
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
	h.Write([]byte("LUX-RLWE-TEE-AUDIT-V1"))
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

// signIntent satisfies approval.CanonicalIntent.
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

func (si *signIntent) Digest() [32]byte {
	h := sha256.New()
	h.Write([]byte("LUX-RLWE-TEE-INTENT-V1"))
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

func (si *signIntent) Bytes() []byte {
	out := make([]byte, 0, 32+32+len(si.env.Kind)+1+32+32+32+32)
	out = append(out, []byte("LUX-RLWE-TEE-INTENT-V1")...)
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
