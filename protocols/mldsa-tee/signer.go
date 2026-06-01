// SPDX-License-Identifier: BSD-3-Clause

package mldsatee

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"

	pulsar "github.com/luxfi/pulsar/ref/go/pkg/pulsar"

	"github.com/luxfi/mpc/pkg/approval"
	"github.com/luxfi/mpc/pkg/hsm"
	"github.com/luxfi/mpc/pkg/kms"
)

// Signer is the institutional-custody ML-DSA signer.
//
// Composition (not inheritance):
//
//   - gate  : kms.ReleaseGate — the trust root.
//   - hsmP  : hsm.Provider     — wraps the master seed at rest.
//   - appr  : approval.ApprovalProvider — out-of-band approval gate.
//   - cfg   : Config           — policy: RIM, hardware, mode, key IDs.
//
// Safe for concurrent Sign calls.
type Signer struct {
	gate kms.ReleaseGate
	hsmP hsm.Provider
	appr approval.ApprovalProvider
	cfg  Config

	params *pulsar.Params

	mu sync.Mutex // reserved for future per-Signer rate-limit state
}

// New builds a Signer from the supplied dependencies.
func New(gate kms.ReleaseGate, hsmP hsm.Provider, appr approval.ApprovalProvider, cfg Config) (*Signer, error) {
	if gate == nil {
		return nil, errors.New("mldsa-tee: nil release gate")
	}
	if hsmP == nil {
		return nil, errors.New("mldsa-tee: nil HSM provider")
	}
	if cfg.ApprovalRequired && appr == nil {
		return nil, errors.New("mldsa-tee: nil approval provider but ApprovalRequired is true")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	params, err := pulsar.ParamsFor(cfg.Mode)
	if err != nil {
		return nil, fmt.Errorf("mldsa-tee: ParamsFor: %w", err)
	}
	return &Signer{
		gate:   gate,
		hsmP:   hsmP,
		appr:   appr,
		cfg:    cfg,
		params: params,
	}, nil
}

// Provision wraps a fresh master seed under the HSM provider for
// later release-gated signing. Generates pulsar.SeedSize (=32) bytes
// of entropy and stores via hsmP.StoreKey under cfg.WrappedSeedKeyID.
// Returns the pulsar.PublicKey derived from the provisioned seed.
func (s *Signer) Provision(ctx context.Context) (*pulsar.PublicKey, error) {
	var seed [pulsar.SeedSize]byte
	defer zeroizeArr(&seed)

	if _, err := rand.Read(seed[:]); err != nil {
		return nil, fmt.Errorf("mldsa-tee: provision: entropy: %w", err)
	}

	if err := s.hsmP.StoreKey(ctx, s.cfg.WrappedSeedKeyID, seed[:]); err != nil {
		return nil, fmt.Errorf("mldsa-tee: provision: HSM StoreKey: %w", err)
	}

	sk, err := pulsar.KeyFromSeed(s.params, seed)
	if err != nil {
		return nil, fmt.Errorf("mldsa-tee: provision: KeyFromSeed: %w", err)
	}
	pub := sk.Public()
	zeroize(sk.Bytes)
	zeroizeArr(&sk.Seed)
	return pub, nil
}

// PublicKey reads the master seed via the HSM provider and derives
// the pulsar PublicKey deterministically. RELEASE-GATE FREE — only
// the at-rest HSM material is read.
func (s *Signer) PublicKey(ctx context.Context) (*pulsar.PublicKey, error) {
	raw, err := s.hsmP.GetKey(ctx, s.cfg.WrappedSeedKeyID)
	if err != nil {
		return nil, fmt.Errorf("mldsa-tee: PublicKey: HSM GetKey: %w", err)
	}
	defer zeroize(raw)
	if len(raw) != pulsar.SeedSize {
		return nil, fmt.Errorf("mldsa-tee: PublicKey: seed length %d does not match pulsar.SeedSize %d", len(raw), pulsar.SeedSize)
	}
	var seed [pulsar.SeedSize]byte
	copy(seed[:], raw)
	defer zeroizeArr(&seed)
	sk, err := pulsar.KeyFromSeed(s.params, seed)
	if err != nil {
		return nil, fmt.Errorf("mldsa-tee: PublicKey: KeyFromSeed: %w", err)
	}
	defer zeroize(sk.Bytes)
	defer zeroizeArr(&sk.Seed)
	return sk.Public(), nil
}

// Mode reports the FIPS 204 parameter set this signer is bound to.
func (s *Signer) Mode() pulsar.Mode { return s.cfg.Mode }

// Params returns the pulsar Params for this signer's mode.
func (s *Signer) Params() *pulsar.Params { return s.params }

// auditedRelease drives the full Issue → approval → composite envelope
// → Release flow.
func (s *Signer) auditedRelease(ctx context.Context, env *Envelope, jobID [32]byte, msg []byte) (kms.SealedSessionKey, error) {
	if env == nil {
		return kms.SealedSessionKey{}, ErrAttestationRequired
	}

	if s.cfg.ApprovalRequired {
		intent := newSignIntent(jobID, msg, env)
		sig, err := s.appr.ApproveIntent(ctx, s.cfg.ApproverID, intent)
		if err != nil {
			return kms.SealedSessionKey{}, fmt.Errorf("%w: %v", ErrApprovalDenied, err)
		}
		ok, err := s.appr.VerifyApproval(ctx, intent, sig)
		if err != nil {
			return kms.SealedSessionKey{}, fmt.Errorf("%w: verify: %v", ErrApprovalDenied, err)
		}
		if !ok {
			return kms.SealedSessionKey{}, ErrApprovalDenied
		}
	}

	nonce, epoch, err := s.gate.Issue(jobID)
	if err != nil {
		return kms.SealedSessionKey{}, fmt.Errorf("%w: gate.Issue: %v", ErrKMSReleaseUnreachable, err)
	}
	env.ExpectedNonce = nonce

	sealed, err := s.gate.Release(kms.ReleaseRequest{
		JobID:       jobID,
		Epoch:       epoch,
		Nonce:       nonce,
		Attestation: env,
		Ctx:         ctx,
	})
	if err != nil {
		return kms.SealedSessionKey{}, fmt.Errorf("%w: %v", ErrPolicyRefused, err)
	}
	return sealed, nil
}

// zeroize clears a byte slice in place.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// zeroizeArr clears a 32-byte array in place.
func zeroizeArr(a *[pulsar.SeedSize]byte) {
	for i := range a {
		a[i] = 0
	}
}
