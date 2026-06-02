// SPDX-License-Identifier: BSD-3-Clause

package slhdsatee

import "errors"

// ChainSecurityProfile is the value the consensus / chain layer
// publishes to express the residency posture it is willing to tolerate
// for SLH-DSA Combine.
//
// Decomplecting: profile is a value, not a place. The chain layer
// constructs it from its ChainConfig (e.g. the precompile
// StrictPQReporter the EVM precompiles use today) and hands it down
// at Sign call time. No global, no init() hook, no env var. The
// dispatcher reads it the same way the precompile contract.RefuseUnderStrictPQ
// helper reads its StrictPQReporter: ONE function, ONE place, ONE
// canonical refusal sentinel.
type ChainSecurityProfile int

const (
	// ProfileLegacyCompat tolerates the strict-atom commodity-host
	// Combine path. The FIPS 205 master bytes transiently exist in
	// the public combiner's SHAKE-expansion buffers for a few
	// microseconds. Acceptable for permissionless / community
	// validation paths where no host is in the TCB; refused for
	// strict-PQ deployments. This is the default.
	ProfileLegacyCompat ChainSecurityProfile = 0

	// ProfileStrictPQ requires every Combine to route through a
	// TEE-attested combiner pool. The master bytes only ever exist
	// inside a measured enclave (SEV-SNP / TDX / NRAS attested
	// host) whose binary / firmware match the operator-asserted RIM
	// and chain-validate to the vendor root. No commodity-host
	// fallback; refusal is hard.
	ProfileStrictPQ ChainSecurityProfile = 1
)

// String reports the canonical wire label for the profile.
func (p ChainSecurityProfile) String() string {
	switch p {
	case ProfileStrictPQ:
		return "strict-PQ"
	case ProfileLegacyCompat:
		return "legacy-compat"
	default:
		return "unknown"
	}
}

// ErrMagnetarNoTEEAttestation is the canonical refusal returned when
// a strict-PQ chain profile attempts to Combine without a valid TEE
// quote. The wire-stable identifier is "ERR_MAGNETAR_NO_TEE_ATTESTATION".
//
// Callers SHOULD switch on errors.Is(err, ErrMagnetarNoTEEAttestation)
// to distinguish profile-gate refusal from upstream attestation /
// release-gate errors.
var ErrMagnetarNoTEEAttestation = errors.New("ERR_MAGNETAR_NO_TEE_ATTESTATION: strict-PQ chain profile requires TEE-attested combiner")

// ErrMagnetarStaleAttestation is returned when an attested combiner's
// last successful re-attestation lies outside the configured rotation
// window. The bytes of the attestation chain-validate but the freshness
// guarantee has lapsed — operators MUST re-attest before the next sign.
var ErrMagnetarStaleAttestation = errors.New("ERR_MAGNETAR_STALE_ATTESTATION: combiner attestation outside rotation window")

// ErrMagnetarInsufficientQuorum is returned when fewer than the
// configured threshold-of-attested-combiners agreed on byte-identical
// output. The pool refuses to surface a signature whose origin is
// less than t attested combiners.
var ErrMagnetarInsufficientQuorum = errors.New("ERR_MAGNETAR_INSUFFICIENT_QUORUM: fewer than threshold attested combiners produced matching signature")

// ErrMagnetarSignatureDivergence is returned when the configured
// quorum DID produce signatures but they were not byte-identical.
// Hard refusal — divergence indicates a misconfigured or compromised
// combiner; the pool MUST NOT silently pick a winner.
var ErrMagnetarSignatureDivergence = errors.New("ERR_MAGNETAR_SIGNATURE_DIVERGENCE: attested combiners produced non-matching signature bytes")
