// SPDX-License-Identifier: BSD-3-Clause

package rlwetee

import (
	"errors"

	"github.com/luxfi/corona/sign"
)

// Config carries the operator-side policy + provider configuration.
//
// Every field is required; New refuses on any zero value.
type Config struct {
	// Threshold is the corona t in t-of-n. corona requires 1 <= t < n.
	Threshold int

	// Participants is the corona n. Each Sign call drives all n
	// parties in-process under the attested TEE; the dispatcher
	// surface remains single-shot.
	Participants int

	// RequiredRIM is the set of acceptable RIM digests.
	RequiredRIM map[[32]byte]struct{}

	// AllowedHardware is the set of acceptable hardware fingerprints.
	AllowedHardware map[[32]byte]struct{}

	// Require* flags mirror kms.ReleasePolicy.Require*.
	RequireSEVSNP bool
	RequireTDX    bool
	RequireNVNRAS bool

	// KMSKeyID is the HSM key for the audit signature over
	// (jobID || msgDigest || epoch || RIM).
	KMSKeyID string

	// WrappedSeedKeyID is the HSM-stored blob identifier for the
	// wrapped 32-byte master trusted-dealer key.
	WrappedSeedKeyID string

	// ApprovalRequired determines whether ApprovalProvider must
	// produce a non-deny ApprovalSignature before Issue().
	ApprovalRequired bool

	// ApproverID is the canonical identifier whose approval is
	// required.
	ApproverID string
}

// Errors surfaced by Config.Validate and the Sign flow.
var (
	ErrInvalidThreshold      = errors.New("rlwe-tee: invalid threshold (requires 1 <= Threshold < Participants)")
	ErrEmptyRIM              = errors.New("rlwe-tee: RequiredRIM must be non-empty (default-deny posture)")
	ErrEmptyHardware         = errors.New("rlwe-tee: AllowedHardware must be non-empty (default-deny posture)")
	ErrNoRequireFlag         = errors.New("rlwe-tee: at least one Require* TEE flag must be true")
	ErrMissingKMSKeyID       = errors.New("rlwe-tee: KMSKeyID required for audit signature")
	ErrMissingSeedKeyID      = errors.New("rlwe-tee: WrappedSeedKeyID required for HSM seed storage")
	ErrApproverMissing       = errors.New("rlwe-tee: ApproverID required when ApprovalRequired is true")
	ErrApprovalDenied        = errors.New("rlwe-tee: approval provider denied or returned mismatched signature")
	ErrAttestationRequired   = errors.New("rlwe-tee: attestation envelope required")
	ErrPolicyRefused         = errors.New("rlwe-tee: release gate refused")
	ErrKMSReleaseUnreachable = errors.New("rlwe-tee: release gate unreachable")
	ErrHSMUnreachable        = errors.New("rlwe-tee: HSM provider unreachable")
	ErrCorruptWrappedSeed    = errors.New("rlwe-tee: wrapped seed blob fails authenticated decryption")
	ErrCoronaProtocol        = errors.New("rlwe-tee: corona threshold protocol failed")
)

// MasterKeySize is the corona trusted-dealer key length the HSM
// stores. Exported so embedders can size buffers consistently with
// the corona kernel.
const MasterKeySize = sign.KeySize // 32

// Validate reports the first structural error in cfg.
func (cfg *Config) Validate() error {
	if cfg.Threshold < 1 || cfg.Participants < 2 || cfg.Threshold >= cfg.Participants {
		return ErrInvalidThreshold
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
