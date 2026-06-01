// SPDX-License-Identifier: BSD-3-Clause

package slhdsatee

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/luxfi/mpc/cc/attest"
	"github.com/luxfi/mpc/pkg/kms"
)

// Envelope is the minimal kms.CompositeAttestation implementation this
// package consumes. It wraps an attested evidence blob (the bytes the
// worker captured via SNP_GUEST_REQUEST / TDREPORT ioctls / NRAS JWT)
// plus the operator-supplied RIM digest, hardware fingerprint, and
// TEE pubkey.
//
// One Envelope per Sign call — no caching. The release gate calls
// Verify(nonce) (cheap nonce check) then VerifyEvidence(ctx, opts...)
// (full chain check via cc/attest). Both must pass.
//
// Wire-form is intentionally NOT defined here: this is a per-process
// composition. The bridge / oracle wire layer that ships attested
// evidence between TEE and operator (or operator and KMS) is the
// responsibility of the calling subsystem. Magnetar's THBS-SE is the
// public-BFT wire spec; this package's Envelope is the institutional-
// custody in-process composition.
type Envelope struct {
	// Kind is the cc/attest evidence kind matching EvidenceBytes
	// framing. Used by Dispatch to route to the right verifier.
	Kind attest.Kind

	// EvidenceBytes is the raw vendor-framed evidence (SEV-SNP report
	// ABI bytes, TDX TDREPORT bytes, NRAS JWT bytes).
	EvidenceBytes []byte

	// ExpectedNonce is the gate-issued challenge nonce the TEE bound
	// into REPORT_DATA before capturing the evidence. Compared by
	// Verify against the kms-supplied expectedNonce.
	ExpectedNonce [32]byte

	// RIM is the operator-asserted RIM digest the TEE measured. The
	// release gate compares RIM against ReleasePolicy.RequiredRIM.
	RIM [32]byte

	// Hardware is the operator-asserted hardware fingerprint
	// (sha256(model||driver||vbios) or platform/chip ID).
	Hardware [32]byte

	// TEEPub is the X25519 public key sealed against — the private
	// half lives only inside the attested TEE.
	TEEPub [32]byte

	// VerifyOpts are forwarded to attest.Dispatch by VerifyEvidence
	// (e.g. WithKDSGetter for offline tests, WithNow for fixed-clock
	// reproducibility, WithExpectedMeasurement to pin the launch
	// digest beyond RIM membership).
	VerifyOpts []attest.Option

	// rimChecker is an optional override used to pin the launch
	// measurement against the verified report. When nil the package
	// uses the default rule: VerifiedReport.Measurement must lie in
	// the operator-supplied RequiredRIM allowlist. This is the
	// orthogonal hook the dispatcher uses to wire RIM membership into
	// the cc/attest chain layer without duplicating policy in two
	// places.
	rimChecker func(*attest.VerifiedReport) error
}

var _ kms.CompositeAttestation = (*Envelope)(nil)

// Verify implements kms.CompositeAttestation.Verify. Returns true iff
// the gate-issued nonce equals the nonce the operator embedded in the
// evidence at TEE-capture time.
//
// This is the cheap pre-chain check. It does NOT prove the evidence
// chains to the vendor root — VerifyEvidence does that. The gate
// calls both in order.
func (e *Envelope) Verify(expectedNonce [32]byte) (bool, error) {
	if subtle.ConstantTimeCompare(e.ExpectedNonce[:], expectedNonce[:]) != 1 {
		return false, nil
	}
	return true, nil
}

// VerifyEvidence implements kms.CompositeAttestation.VerifyEvidence.
//
// Dispatches the single evidence blob to cc/attest, returns the
// verified report on success, surfaces any chain / signature / policy
// failure via ErrChainInvalid / ErrSignatureInvalid / ErrPolicy. The
// gate translates these into ErrAttestationChain wrapped under
// ErrPolicyRefused.
//
// Additionally enforces that the operator-asserted RIM equals the
// VerifiedReport.Measurement after chain validation. This is the
// composition step: the gate checks RIM membership in its allowlist;
// VerifyEvidence checks the report Measurement equals the operator-
// asserted RIM. Together: a chain-validated report whose Measurement
// is in the gate's RequiredRIM set.
func (e *Envelope) VerifyEvidence(ctx context.Context, opts ...attest.Option) ([]*attest.VerifiedReport, error) {
	if len(e.EvidenceBytes) == 0 {
		return nil, fmt.Errorf("%w: empty evidence", attest.ErrInvalidEvidence)
	}
	allOpts := append([]attest.Option{}, e.VerifyOpts...)
	allOpts = append(allOpts, opts...)
	rep, err := attest.Dispatch(ctx, e.Kind, e.EvidenceBytes, allOpts...)
	if err != nil {
		return nil, err
	}

	if e.rimChecker != nil {
		if err := e.rimChecker(rep); err != nil {
			return nil, err
		}
	} else {
		if err := defaultRIMCheck(rep, e.RIM); err != nil {
			return nil, err
		}
	}
	return []*attest.VerifiedReport{rep}, nil
}

// RIMDigest implements kms.CompositeAttestation.RIMDigest.
func (e *Envelope) RIMDigest() [32]byte { return e.RIM }

// HardwareFingerprint implements kms.CompositeAttestation.HardwareFingerprint.
func (e *Envelope) HardwareFingerprint() [32]byte { return e.Hardware }

// TEEPublicKey implements kms.CompositeAttestation.TEEPublicKey.
func (e *Envelope) TEEPublicKey() [32]byte { return e.TEEPub }

// EvidenceIssuers implements kms.CompositeAttestation.EvidenceIssuers.
//
// One issuer per envelope (this construction binds one TEE quote per
// sign request). If composite (CPU TEE + GPU NRAS) is required, the
// operator MUST run Sign once per quorum member and combine results;
// for the institutional-custody case here, one CPU TEE quote is the
// canonical posture.
func (e *Envelope) EvidenceIssuers() []string {
	switch e.Kind {
	case attest.KindSEVSNP:
		return []string{kms.IssuerSEVSNP}
	case attest.KindTDX:
		return []string{kms.IssuerTDX}
	case attest.KindNRAS:
		return []string{kms.IssuerNVNRAS}
	default:
		return nil
	}
}

// defaultRIMCheck verifies the cc/attest verified-report Measurement
// matches the operator-asserted RIM digest. We sha256-fold the raw
// measurement bytes (variable-length per evidence kind: 48 bytes for
// SEV-SNP, MRTD for TDX, derived for NRAS) into the 32-byte RIM
// digest convention used by the gate's allowlist.
//
// Folding is one-way and stable: sha256(measurement) is the operator-
// asserted RIM identifier; the release gate's RequiredRIM is the
// allowlist of such identifiers; the worker that captured this
// evidence claimed to be measuring RIM X; defaultRIMCheck enforces
// that X equals sha256(measurement) of the chain-validated report.
//
// Constant-time compare to avoid timing leaks on partial-RIM match.
func defaultRIMCheck(rep *attest.VerifiedReport, expected [32]byte) error {
	if rep == nil {
		return errors.New("slhdsa-tee: defaultRIMCheck: nil verified report")
	}
	got := sha256.Sum256(rep.Measurement)
	if subtle.ConstantTimeCompare(got[:], expected[:]) != 1 {
		return fmt.Errorf("%w: report measurement does not fold to operator-asserted RIM", attest.ErrPolicy)
	}
	return nil
}
