// SPDX-License-Identifier: BSD-3-Clause
package thresholdd

import (
	"time"

	"github.com/google/go-sev-guest/verify/trust"

	"github.com/luxfi/mpc/cc/attest"
)

// Shared TEE-only options + helpers consumed by every scheme's
// Sign_TEE method. Decomplecting: every TEE scheme (slhdsa, mldsa,
// rlwe) consumes the same set of cc/attest.Option values, so we name
// them once here rather than duplicate across each dispatcher file.

// slhdsateeVerifyOpt is the dispatcher-side option carrier used by
// Sign_TEE. We expose this concrete type rather than the cc/attest
// internal config so embedders that drive the dispatcher do not need
// to import luxfi/mpc/cc/attest directly.
//
// The name is shared across slhdsa-tee / mldsa-tee / rlwe-tee
// dispatcher entry points; the type-safe distinction the caller
// needs is the value-builder (NewKDSReplay, WithNow, etc.), not the
// scheme name.
type slhdsateeVerifyOpt struct {
	// nowOverride pins the verifier wall clock. Tests use this to
	// stay inside a committed VCEK's validity window.
	nowOverride time.Time
	// kdsGetter installs a custom HTTPSGetter for SEV-SNP / TDX
	// chain fetch. Tests use this to replay pre-fetched bytes.
	kdsGetter trust.HTTPSGetter
	// expectedReportData pins the byte-level REPORT_DATA / REPORTDATA
	// field of the evidence (kind-specific 64-byte field on SEV/TDX,
	// JWT claim on NRAS). Production callers MUST bind their
	// gate-issued nonce here.
	expectedReportData []byte
	// expectedMeasurement pins a known-good launch digest. Tests
	// usually omit so the membership-check via the gate's
	// RequiredRIM allowlist is the authority.
	expectedMeasurement []byte
}

// TEEVerifyOption is the public alias for the dispatcher's verify
// option carrier. Embedders construct values via WithNow /
// WithKDSGetter / WithExpectedReportData / WithExpectedMeasurement.
type TEEVerifyOption = slhdsateeVerifyOpt

// WithNow pins the verification clock. Tests use this to stay inside
// a committed VCEK / TDX-quote validity window.
func WithNow(t time.Time) TEEVerifyOption {
	return slhdsateeVerifyOpt{nowOverride: t}
}

// WithKDSGetter installs an HTTPSGetter override for the AMD KDS
// (SEV-SNP) / Intel PCS (TDX) / NRAS JWKS endpoints.
func WithKDSGetter(g trust.HTTPSGetter) TEEVerifyOption {
	return slhdsateeVerifyOpt{kdsGetter: g}
}

// WithExpectedReportData pins the byte-level REPORT_DATA field of
// the evidence. Production callers MUST bind their gate-issued
// nonce here.
func WithExpectedReportData(want []byte) TEEVerifyOption {
	buf := make([]byte, len(want))
	copy(buf, want)
	return slhdsateeVerifyOpt{expectedReportData: buf}
}

// WithExpectedMeasurement pins a known-good launch digest beyond the
// gate's RIM allowlist.
func WithExpectedMeasurement(want []byte) TEEVerifyOption {
	buf := make([]byte, len(want))
	copy(buf, want)
	return slhdsateeVerifyOpt{expectedMeasurement: buf}
}

// teeVerifyOptionsToAttest converts the dispatcher's options into the
// underlying cc/attest.Option list. Splitting this out keeps the
// per-scheme Sign_TEE implementations identical.
func teeVerifyOptionsToAttest(opts []slhdsateeVerifyOpt) []attest.Option {
	out := make([]attest.Option, 0, len(opts))
	for _, o := range opts {
		if !o.nowOverride.IsZero() {
			out = append(out, attest.WithNow(o.nowOverride))
		}
		if o.kdsGetter != nil {
			out = append(out, attest.WithKDSGetter(o.kdsGetter))
		}
		if o.expectedReportData != nil {
			out = append(out, attest.WithExpectedReportData(o.expectedReportData))
		}
		if o.expectedMeasurement != nil {
			out = append(out, attest.WithExpectedMeasurement(o.expectedMeasurement))
		}
	}
	return out
}

// attestKindFromString parses the wire-stable evidence-kind string
// into the cc/attest.Kind enum. Unknown kinds map to the empty kind
// which Dispatch rejects with ErrUnsupportedKind — the dispatcher
// surface then surfaces that as a hard refusal.
func attestKindFromString(s string) attest.Kind {
	switch s {
	case "sev_snp":
		return attest.KindSEVSNP
	case "tdx":
		return attest.KindTDX
	case "nras":
		return attest.KindNRAS
	default:
		return attest.Kind(s)
	}
}
