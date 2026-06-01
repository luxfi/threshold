// SPDX-License-Identifier: BSD-3-Clause

package rlwetee

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	coronaThreshold "github.com/luxfi/corona/threshold"

	"github.com/luxfi/mpc/pkg/approval"
	"github.com/luxfi/mpc/pkg/hsm"
	"github.com/luxfi/mpc/pkg/kms"
)

// coronaSerializer serializes every call into corona.threshold.
//
// corona.threshold.GenerateKeys writes package-level globals
// (sign.K, sign.Threshold) — see corona/threshold/threshold.go:122-124.
// Two concurrent callers stomp on those globals and produce
// out-of-bounds slice errors deep in primitives.ShamirSecretSharing.
//
// Until corona makes its threshold API stateless we wrap every entry
// point with this mutex. This is an upstream-constraint workaround,
// not a security boundary; the mutex is package-level because the
// shared state is package-level.
var coronaSerializer sync.Mutex

// Signer is the institutional-custody Ring-LWE signer.
//
// Composition:
//
//   - gate  : kms.ReleaseGate                — trust root.
//   - hsmP  : hsm.Provider                   — wraps the master trusted-dealer key.
//   - appr  : approval.ApprovalProvider      — out-of-band approval gate.
//   - cfg   : Config                         — policy: RIM, hardware, t-of-n, key IDs.
//
// Safe for concurrent Sign calls.
type Signer struct {
	gate kms.ReleaseGate
	hsmP hsm.Provider
	appr approval.ApprovalProvider
	cfg  Config

	mu sync.Mutex // reserved for future per-Signer rate-limit state
}

// New builds a Signer.
func New(gate kms.ReleaseGate, hsmP hsm.Provider, appr approval.ApprovalProvider, cfg Config) (*Signer, error) {
	if gate == nil {
		return nil, errors.New("rlwe-tee: nil release gate")
	}
	if hsmP == nil {
		return nil, errors.New("rlwe-tee: nil HSM provider")
	}
	if cfg.ApprovalRequired && appr == nil {
		return nil, errors.New("rlwe-tee: nil approval provider but ApprovalRequired is true")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Signer{
		gate: gate,
		hsmP: hsmP,
		appr: appr,
		cfg:  cfg,
	}, nil
}

// Provision wraps a fresh MasterKeySize-byte trusted-dealer key under
// the HSM provider for later release-gated signing.
//
// The master key is generated from crypto/rand and stored via
// hsmP.StoreKey under cfg.WrappedSeedKeyID. We then derive the
// GroupKey once to return to the caller — embedders register that as
// the canonical group public key on the wire.
func (s *Signer) Provision(ctx context.Context) (*coronaThreshold.GroupKey, error) {
	key := make([]byte, MasterKeySize)
	defer zeroize(key)

	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("rlwe-tee: provision: entropy: %w", err)
	}

	if err := s.hsmP.StoreKey(ctx, s.cfg.WrappedSeedKeyID, key); err != nil {
		return nil, fmt.Errorf("rlwe-tee: provision: HSM StoreKey: %w", err)
	}

	// Materialize the GroupKey by re-running the deterministic dealer
	// path with the fresh master key seeding the entropy. corona's
	// GenerateKeys reads sign.KeySize bytes from randSource — pass a
	// bytes.Reader so the run is reproducible. coronaSerializer
	// guards the corona-internal global writes.
	coronaSerializer.Lock()
	_, gk, err := coronaThreshold.GenerateKeys(s.cfg.Threshold, s.cfg.Participants, bytes.NewReader(key))
	coronaSerializer.Unlock()
	if err != nil {
		return nil, fmt.Errorf("rlwe-tee: provision: GenerateKeys: %w", err)
	}
	return gk, nil
}

// PublicKey reads the master key via the HSM provider and derives
// the corona GroupKey deterministically. RELEASE-GATE FREE — only
// the at-rest HSM material is read.
func (s *Signer) PublicKey(ctx context.Context) (*coronaThreshold.GroupKey, error) {
	key, err := s.hsmP.GetKey(ctx, s.cfg.WrappedSeedKeyID)
	if err != nil {
		return nil, fmt.Errorf("rlwe-tee: PublicKey: HSM GetKey: %w", err)
	}
	defer zeroize(key)
	if len(key) != MasterKeySize {
		return nil, fmt.Errorf("rlwe-tee: PublicKey: key length %d does not match MasterKeySize %d", len(key), MasterKeySize)
	}
	coronaSerializer.Lock()
	_, gk, err := coronaThreshold.GenerateKeys(s.cfg.Threshold, s.cfg.Participants, bytes.NewReader(key))
	coronaSerializer.Unlock()
	if err != nil {
		return nil, fmt.Errorf("rlwe-tee: PublicKey: GenerateKeys: %w", err)
	}
	return gk, nil
}

// Threshold reports the corona t.
func (s *Signer) Threshold() int { return s.cfg.Threshold }

// Participants reports the corona n.
func (s *Signer) Participants() int { return s.cfg.Participants }

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

func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// sessionIDFromJobID folds a 32-byte jobID into the small int the
// corona kernel's session-ID field needs. corona.threshold's session
// ID is `int`, so we take the first 31 bits of sha256(jobID) — strips
// the sign bit to stay in non-negative int range on all platforms.
func sessionIDFromJobID(jobID [32]byte) int {
	d := sha256.Sum256(jobID[:])
	v := int(d[0])<<23 | int(d[1])<<15 | int(d[2])<<7 | int(d[3]>>1)
	return v
}
