// SPDX-License-Identifier: BSD-3-Clause

package slhdsatee

import (
	"errors"
	"fmt"

	magnetar "github.com/luxfi/magnetar/ref/go/pkg/magnetar"
)

// Config carries the operator-side policy + provider configuration.
//
// Every field is required; New refuses on any zero value. There is no
// "default-friendly" path — institutional custody never starts with an
// empty allowlist or an unset KMS root.
type Config struct {
	// Mode pins the FIPS 205 parameter set. Production institutional
	// custody uses ModeM192s (recommended) or ModeM256s for the most
	// conservative posture. Mode is bound into Signer.params at
	// construction and into the keypair derived from the unwrapped
	// master seed.
	Mode magnetar.Mode

	// RequiredRIM is the set of acceptable Reference-Integrity-Manifest
	// digests for the worker that holds the wrapped master seed. A
	// release-gate refusal here means the worker binary or the TEE
	// firmware does not match a known-good measurement.
	//
	// Wire bytes: SHA-256 of the canonical RIM document. Mirrors
	// luxfi/mpc/pkg/kms.ReleasePolicy.RequiredRIM.
	RequiredRIM map[[32]byte]struct{}

	// AllowedHardware is the set of acceptable hardware-fingerprint
	// digests (sha256(model || driver || vbios) for GPU paths,
	// platform/chip ID for CPU-only).
	AllowedHardware map[[32]byte]struct{}

	// RequireSEVSNP / RequireTDX / RequireNVNRAS mirror
	// kms.ReleasePolicy.Require* — at least one MUST be true for any
	// non-test deployment. The composite envelope produced here will
	// surface its evidence issuers via the kms.CompositeAttestation
	// interface so the gate's default-deny posture fires correctly.
	RequireSEVSNP bool
	RequireTDX    bool
	RequireNVNRAS bool

	// KMSKeyID is the HSM key identifier under which the wrapped
	// master seed is stored. The HSM provider's Sign API is not used
	// for the SLH-DSA inner-sign (FIPS 205 has no native HSM offload
	// today); we use it to delegate ANCILLARY ECDSA-P256 audit
	// signatures over the (jobID, msg, sealedKey.Epoch, RIM) tuple so
	// every release is independently auditable. The master seed
	// itself is stored as raw bytes via HSM Provider.GetKey /
	// StoreKey under WrappedSeedKeyID.
	KMSKeyID string

	// WrappedSeedKeyID is the HSM-stored blob identifier for the
	// AEAD-wrapped master seed. The blob is opened ONLY inside the
	// TEE after gate.Release returns a sealed session key. The HSM
	// holds ciphertext; the TEE holds plaintext for the duration of
	// one sign call; the host process never sees plaintext.
	WrappedSeedKeyID string

	// ApprovalRequired determines whether ApprovalProvider must
	// produce a non-deny ApprovalSignature before Issue() is called.
	// Production institutional custody MUST set this true. Test mode
	// may set false to exercise the chain-verify + release path in
	// isolation.
	ApprovalRequired bool

	// ApproverID is the canonical identifier (email, DID, KMS ARN)
	// whose approval is required. Used as the lookup key against the
	// configured ApprovalProvider. Empty rejects when
	// ApprovalRequired is true.
	ApproverID string
}

// Errors surfaced by Config.Validate. Distinguished by errors.Is so
// callers (operator boot scripts, helm chart smoke tests) can switch.
var (
	ErrInvalidMode          = errors.New("slhdsa-tee: invalid magnetar mode")
	ErrEmptyRIM             = errors.New("slhdsa-tee: RequiredRIM must be non-empty (default-deny posture)")
	ErrEmptyHardware        = errors.New("slhdsa-tee: AllowedHardware must be non-empty (default-deny posture)")
	ErrNoRequireFlag        = errors.New("slhdsa-tee: at least one Require* TEE flag must be true")
	ErrMissingKMSKeyID      = errors.New("slhdsa-tee: KMSKeyID required for audit signature")
	ErrMissingSeedKeyID     = errors.New("slhdsa-tee: WrappedSeedKeyID required for HSM seed storage")
	ErrApproverMissing      = errors.New("slhdsa-tee: ApproverID required when ApprovalRequired is true")
	ErrApprovalDenied       = errors.New("slhdsa-tee: approval provider denied or returned mismatched signature")
	ErrAttestationRequired  = errors.New("slhdsa-tee: attestation envelope required (cannot sign without TEE evidence)")
	ErrPolicyRefused        = errors.New("slhdsa-tee: release gate refused (RIM, hardware, nonce, or chain verify)")
	ErrKMSReleaseUnreachable = errors.New("slhdsa-tee: release gate unreachable")
	ErrHSMUnreachable       = errors.New("slhdsa-tee: HSM provider unreachable")
	ErrCorruptWrappedSeed   = errors.New("slhdsa-tee: wrapped seed blob fails authenticated decryption")
)

// Validate reports the first structural error in cfg. There is no
// "warnings" return — institutional-custody policy is hard or it is
// nothing.
func (cfg *Config) Validate() error {
	if _, err := magnetar.ParamsFor(cfg.Mode); err != nil {
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
