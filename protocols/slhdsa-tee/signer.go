// SPDX-License-Identifier: BSD-3-Clause

package slhdsatee

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	magnetar "github.com/luxfi/magnetar/ref/go/pkg/magnetar"
	"github.com/luxfi/mpc/pkg/approval"
	"github.com/luxfi/mpc/pkg/hsm"
	"github.com/luxfi/mpc/pkg/kms"
)

// Signer is the institutional-custody SLH-DSA signer.
//
// Composition (not inheritance):
//
//   - gate  : kms.ReleaseGate — the trust root.
//   - hsmP  : hsm.Provider     — wraps the master seed at rest.
//   - appr  : approval.ApprovalProvider — out-of-band human/programmatic gate.
//   - cfg   : Config           — policy: RIM, hardware, mode, key IDs.
//
// Each is independently complete and replaceable. No subclassing, no
// hidden state — the four fields name the four responsibilities, and
// every Sign call drives them in a fixed order.
//
// The Signer instance can be reused across many Sign calls. It is
// safe for concurrent use; per-call state (sealed key, plaintext
// seed) is stack-local and zeroized on return.
type Signer struct {
	gate kms.ReleaseGate
	hsmP hsm.Provider
	appr approval.ApprovalProvider
	cfg  Config

	params *magnetar.Params

	// mu protects nothing today — both gate and hsmP are themselves
	// thread-safe — but reserved for future per-Signer rate-limit /
	// counter state without changing the public API.
	mu sync.Mutex
}

// New builds a Signer from the supplied dependencies.
//
// All four parameters are required. nil hsmP or nil gate or nil
// approval (when ApprovalRequired) is a construction error — there is
// no "best effort" fallback path.
func New(gate kms.ReleaseGate, hsmP hsm.Provider, appr approval.ApprovalProvider, cfg Config) (*Signer, error) {
	if gate == nil {
		return nil, errors.New("slhdsa-tee: nil release gate")
	}
	if hsmP == nil {
		return nil, errors.New("slhdsa-tee: nil HSM provider")
	}
	if cfg.ApprovalRequired && appr == nil {
		return nil, errors.New("slhdsa-tee: nil approval provider but ApprovalRequired is true")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	params, err := magnetar.ParamsFor(cfg.Mode)
	if err != nil {
		return nil, fmt.Errorf("slhdsa-tee: ParamsFor: %w", err)
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
// later release-gated signing. Called once at operator bootstrap (or
// at scheduled rotation). The seed bytes are zeroized after storage.
//
// In a real institutional deployment, Provision runs inside the
// attested TEE itself — the operator captures attestation, calls
// gate.Issue, gate.Release, derives the wrapping key from the sealed
// session key, AEAD-wraps the seed, and StoreKey the ciphertext. The
// HSM holds wrapped bytes; the TEE holds plaintext only ephemerally.
//
// For this package's surface, Provision is purposefully simple: it
// generates a fresh seed of params.SeedSize bytes and stores it via
// hsmP.StoreKey under cfg.WrappedSeedKeyID. Wrapping under the TEE
// session-key is the next composition step the embedder layers on
// top — see ExampleEmbedding in the README.
//
// Production deployments using a KMS-backed HSM (AWS KMS, Azure Key
// Vault, GCP KMS) get at-rest encryption from the cloud HSM itself;
// adding AEAD-wrapping is defense-in-depth, not the trust root.
//
// Returns the magnetar.PublicKey derived from the provisioned seed
// so the embedder can register it as the canonical group public key.
func (s *Signer) Provision(ctx context.Context, rng *seedRNG) (*magnetar.PublicKey, error) {
	seed := make([]byte, s.params.SeedSize)
	defer zeroize(seed)

	if rng == nil {
		if _, err := rand.Read(seed); err != nil {
			return nil, fmt.Errorf("slhdsa-tee: provision: entropy: %w", err)
		}
	} else {
		if _, err := rng.Read(seed); err != nil {
			return nil, fmt.Errorf("slhdsa-tee: provision: deterministic seed: %w", err)
		}
	}

	if err := s.hsmP.StoreKey(ctx, s.cfg.WrappedSeedKeyID, seed); err != nil {
		return nil, fmt.Errorf("slhdsa-tee: provision: HSM StoreKey: %w", err)
	}

	sk, err := magnetar.KeyFromSeed(s.params, seed)
	if err != nil {
		return nil, fmt.Errorf("slhdsa-tee: provision: KeyFromSeed: %w", err)
	}
	pub := sk.Public()
	// Zeroize the secret key bytes — only the public key escapes.
	zeroize(sk.Bytes)
	zeroize(sk.Seed)
	return pub, nil
}

// PublicKey reads the master seed via the HSM provider and derives
// the magnetar PublicKey deterministically. Used by callers that
// need the wire-form group public key without performing a sign.
//
// The seed is loaded into a stack-local buffer and zeroized on
// return; the derived PrivateKey's seed copy is also zeroized.
//
// PublicKey is RELEASE-GATE FREE — it only reads the at-rest HSM
// material. The TEE-attested release gate is exercised by Sign, not
// by PublicKey. This matches the standard "public material is
// public, private material is gated" separation.
//
// For deployments where even the public key is a custody secret
// (rare; usually pkBytes are published on-chain), do not call this
// method — embed the published group public key independently.
func (s *Signer) PublicKey(ctx context.Context) (*magnetar.PublicKey, error) {
	seed, err := s.hsmP.GetKey(ctx, s.cfg.WrappedSeedKeyID)
	if err != nil {
		return nil, fmt.Errorf("slhdsa-tee: PublicKey: HSM GetKey: %w", err)
	}
	defer zeroize(seed)
	if len(seed) != s.params.SeedSize {
		return nil, fmt.Errorf("slhdsa-tee: PublicKey: seed length %d does not match SeedSize %d (mode=%s)",
			len(seed), s.params.SeedSize, s.params.Mode)
	}
	sk, err := magnetar.KeyFromSeed(s.params, seed)
	if err != nil {
		return nil, fmt.Errorf("slhdsa-tee: PublicKey: KeyFromSeed: %w", err)
	}
	defer zeroize(sk.Bytes)
	defer zeroize(sk.Seed)
	return sk.Public(), nil
}

// Mode reports the FIPS 205 parameter set this signer is bound to.
// Embedders use this to label published signatures (M192s / M192f /
// M256s) when the wire form does not already carry the mode.
func (s *Signer) Mode() magnetar.Mode { return s.cfg.Mode }

// Params returns the magnetar Params for this signer's mode. Exposed
// for embedders that need to call magnetar.Verify / VerifyBytes with
// the matching params.
func (s *Signer) Params() *magnetar.Params { return s.params }

// auditedRelease drives the full Issue → approval → composite-envelope
// → Release flow and returns the SealedSessionKey on success. Each
// failure mode wraps a sentinel from config.go so callers can branch
// on errors.Is without parsing strings.
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
		// gate.Release wraps kms.ErrPolicyRefused / ErrAttestationChain
		// already — surface verbatim so callers using errors.Is can
		// catch the kms sentinels directly.
		return kms.SealedSessionKey{}, fmt.Errorf("%w: %v", ErrPolicyRefused, err)
	}
	return sealed, nil
}

// zeroize clears a byte slice in place. The compiler is NOT permitted
// to elide this loop (the package's tests inspect the buffer
// post-call). Stable across Go versions.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// seedRNG is a thin alias for the deterministic-RNG path used by
// Provision in tests. Defined here so Provision's signature stays
// stable; the in-test impl lives in signer_test.go.
type seedRNG struct {
	src []byte
	off int
}

// Read implements io.Reader.
func (r *seedRNG) Read(p []byte) (int, error) {
	if r.off >= len(r.src) {
		return 0, errEndOfSeedRNG
	}
	n := copy(p, r.src[r.off:])
	r.off += n
	return n, nil
}

var errEndOfSeedRNG = errors.New("slhdsa-tee: seedRNG exhausted")

// newTestClock returns a stable clock for tests. Production paths use
// time.Now via gate / hsm internals; this helper exists so test code
// has one obvious source of timestamps when constructing
// ApprovalSignatures or audit records.
func newTestClock() func() time.Time {
	return func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
}
