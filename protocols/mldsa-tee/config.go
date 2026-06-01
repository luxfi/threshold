// SPDX-License-Identifier: BSD-3-Clause

package mldsatee

import (
	"errors"
	"fmt"

	pulsar "github.com/luxfi/pulsar/ref/go/pkg/pulsar"
)

// Config carries the operator-side policy + provider configuration.
//
// Every field is required; New refuses on any zero value. There is
// no "default-friendly" path — institutional custody never starts
// with an empty allowlist or an unset KMS root.
type Config struct {
	// Mode pins the FIPS 204 parameter set. Production institutional
	// custody uses ModeP65 (recommended, NIST PQ category 3) or
	// ModeP87 for the most conservative posture. Mode is bound into
	// Signer.params at construction and into the keypair derived
	// from the unwrapped master seed.
	Mode pulsar.Mode

	// RequiredRIM is the set of acceptable Reference-Integrity-Manifest
	// digests for the worker that holds the wrapped master seed.
	RequiredRIM map[[32]byte]struct{}

	// AllowedHardware is the set of acceptable hardware-fingerprint
	// digests.
	AllowedHardware map[[32]byte]struct{}

	// RequireSEVSNP / RequireTDX / RequireNVNRAS mirror
	// kms.ReleasePolicy.Require* — at least one MUST be true.
	RequireSEVSNP bool
	RequireTDX    bool
	RequireNVNRAS bool

	// KMSKeyID is the HSM key identifier used for the audit
	// signature over (jobID || msgDigest || epoch || RIM).
	KMSKeyID string

	// WrappedSeedKeyID is the HSM-stored blob identifier for the
	// wrapped 32-byte master ML-DSA seed.
	WrappedSeedKeyID string

	// ApprovalRequired determines whether ApprovalProvider must
	// produce a non-deny ApprovalSignature before Issue() is called.
	ApprovalRequired bool

	// ApproverID is the canonical identifier (email, DID, KMS ARN)
	// whose approval is required.
	ApproverID string
}

// Errors surfaced by Config.Validate and the Sign flow.
var (
	ErrInvalidMode           = errors.New("mldsa-tee: invalid pulsar mode")
	ErrEmptyRIM              = errors.New("mldsa-tee: RequiredRIM must be non-empty (default-deny posture)")
	ErrEmptyHardware         = errors.New("mldsa-tee: AllowedHardware must be non-empty (default-deny posture)")
	ErrNoRequireFlag         = errors.New("mldsa-tee: at least one Require* TEE flag must be true")
	ErrMissingKMSKeyID       = errors.New("mldsa-tee: KMSKeyID required for audit signature")
	ErrMissingSeedKeyID      = errors.New("mldsa-tee: WrappedSeedKeyID required for HSM seed storage")
	ErrApproverMissing       = errors.New("mldsa-tee: ApproverID required when ApprovalRequired is true")
	ErrApprovalDenied        = errors.New("mldsa-tee: approval provider denied or returned mismatched signature")
	ErrAttestationRequired   = errors.New("mldsa-tee: attestation envelope required")
	ErrPolicyRefused         = errors.New("mldsa-tee: release gate refused")
	ErrKMSReleaseUnreachable = errors.New("mldsa-tee: release gate unreachable")
	ErrHSMUnreachable        = errors.New("mldsa-tee: HSM provider unreachable")
	ErrCorruptWrappedSeed    = errors.New("mldsa-tee: wrapped seed blob fails authenticated decryption")
)

// Validate reports the first structural error in cfg.
func (cfg *Config) Validate() error {
	if _, err := pulsar.ParamsFor(cfg.Mode); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidMode, err)
	}
	if len(cfg.RequiredRIM) == 0 {
		return ErrEmptyRIM
	}
	if len(cfg.AllowedHardware) == 0 {
		return ErrEmptyHardware
	}
	if !cfg.RequireSEVSNP && !cfg.RequireTDX && !cfg.RequireNVNRAS {
		return ErrNoRequireFlag
	}
	if cfg.KMSKeyID == "" {
		return ErrMissingKMSKeyID
	}
	if cfg.WrappedSeedKeyID == "" {
		return ErrMissingSeedKeyID
	}
	if cfg.ApprovalRequired && cfg.ApproverID == "" {
		return ErrApproverMissing
	}
	return nil
}
