// SPDX-License-Identifier: BSD-3-Clause

package slhdsatee

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/luxfi/mpc/cc/attest"
)

// CombinerPool is the t-of-n attested-combiner registry the strict-PQ
// profile binds Combine through.
//
// Composition:
//
//   - Each AttestedCombiner is one of (SEV-SNP / TDX / NRAS) and holds
//     a Signer + the last successful VerifiedReport's IssuedAt.
//   - The pool is parameterised by (Threshold, RotationWindow,
//     KnownIssuers, Now). Threshold is the t-of-n quorum required for
//     a Combine to surface a signature. RotationWindow bounds the age
//     of each combiner's attestation: a Combine call that finds any
//     selected combiner outside the window refuses with
//     ErrMagnetarStaleAttestation BEFORE reaching that combiner's
//     signer.
//   - KnownIssuers is the set of vendor strings the pool is willing to
//     accept under the active chain profile (e.g. {"amd.sev.snp",
//     "intel.tdx", "nvidia.nras.v1"}); a combiner whose verified-report
//     Vendor is not in this set is refused.
//
// Hickey discipline: pool state is one value; mutation goes through
// the API; concurrent Combine calls observe the same snapshot for the
// duration of one call (under RLock).
type CombinerPool struct {
	mu        sync.RWMutex
	threshold int
	rotation  time.Duration
	issuers   map[string]struct{}
	members   []*PoolMember
	now       func() time.Time
}

// PoolMember binds one attested combiner endpoint to its current
// attestation freshness state. The Signer is the slhdsa-tee.Signer
// that holds the wrapped seed for THIS combiner (one wrapped seed
// per attested host); the LastVerifiedReport is what
// pool.Attest() refreshes when the operator submits a new quote.
type PoolMember struct {
	// Name is the operator-supplied identifier for this combiner
	// endpoint (e.g. "us-east-1a-snp-01"). Used in audit logs and to
	// disambiguate members in pool errors.
	Name string

	// Signer is the slhdsa-tee.Signer wired to this combiner. The
	// pool delegates the actual Sign call to Signer.Sign once the
	// pool-level freshness gate has accepted the most recent quote.
	Signer *Signer

	// mu protects LastReport / LastIssuedAt. Per-member lock so
	// Attest() on one member does not block Combine on another.
	mu           sync.RWMutex
	LastReport   *attest.VerifiedReport
	LastIssuedAt time.Time
}

// CombinerPoolConfig captures pool-level policy.
type CombinerPoolConfig struct {
	// Threshold is the t in t-of-n. MUST be >= 2; the user mandate
	// explicitly calls for "at least 2-of-3 attested combiners must
	// produce matching signature for it to be accepted".
	Threshold int

	// RotationWindow bounds the age of each combiner's attestation.
	// Outside this window, Combine refuses with
	// ErrMagnetarStaleAttestation. Production deployments rotate per
	// epoch (Lux block-time epoch == ~1s currently); a 60s rotation
	// window absorbs ~60 blocks of latency between operator
	// re-attestation and the next sign request.
	RotationWindow time.Duration

	// KnownIssuers is the set of vendor strings the pool admits.
	// For strict-PQ production deployments, this is typically
	// {"amd.sev.snp"} (the only production-attestable verifier today;
	// TDX and NRAS are stubs at cc/attest tracked #222). The
	// dispatcher fails fast on a Combine that selects an issuer not
	// in this set.
	KnownIssuers map[string]struct{}

	// Now is the wall-clock source. Production leaves this nil so
	// the pool uses time.Now; tests pin it for deterministic rotation
	// windows.
	Now func() time.Time
}

// NewCombinerPool builds an empty pool from cfg. Members are added
// via AddMember; the pool is empty until at least Threshold members
// are registered + attested.
func NewCombinerPool(cfg CombinerPoolConfig) (*CombinerPool, error) {
	if cfg.Threshold < 2 {
		return nil, fmt.Errorf("slhdsa-tee: CombinerPool requires Threshold >= 2 (got %d)", cfg.Threshold)
	}
	if cfg.RotationWindow <= 0 {
		return nil, fmt.Errorf("slhdsa-tee: CombinerPool requires RotationWindow > 0 (got %s)", cfg.RotationWindow)
	}
	if len(cfg.KnownIssuers) == 0 {
		return nil, errors.New("slhdsa-tee: CombinerPool requires at least one KnownIssuer (default-deny posture)")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	p := &CombinerPool{
		threshold: cfg.Threshold,
		rotation:  cfg.RotationWindow,
		issuers:   make(map[string]struct{}, len(cfg.KnownIssuers)),
		now:       now,
	}
	for k := range cfg.KnownIssuers {
		p.issuers[k] = struct{}{}
	}
	return p, nil
}

// AddMember registers an attested combiner endpoint. The member is
// NOT yet sign-eligible — Attest must be called with a fresh quote
// before it counts toward the quorum.
func (p *CombinerPool) AddMember(name string, signer *Signer) (*PoolMember, error) {
	if signer == nil {
		return nil, errors.New("slhdsa-tee: CombinerPool.AddMember: nil Signer")
	}
	if name == "" {
		return nil, errors.New("slhdsa-tee: CombinerPool.AddMember: empty Name")
	}
	m := &PoolMember{Name: name, Signer: signer}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, existing := range p.members {
		if existing.Name == name {
			return nil, fmt.Errorf("slhdsa-tee: CombinerPool.AddMember: duplicate member %q", name)
		}
	}
	p.members = append(p.members, m)
	return m, nil
}

// Attest refreshes a member's attestation freshness state. The caller
// supplies (env, jobID) — the pool calls env.VerifyEvidence to drive
// the chain-validation, checks the resulting report's Vendor against
// KnownIssuers, and pins the LastIssuedAt to the pool clock on
// success. Failure leaves the prior state untouched (no half-update).
//
// Attest is called by the operator's control-plane out-of-band of any
// Sign call: a control-plane tick captures fresh quotes from each
// combiner and submits them. The Combine path is then a freshness
// READ — it never blocks on a network roundtrip to KDS / PCS / NRAS.
func (p *CombinerPool) Attest(ctx context.Context, memberName string, env *Envelope) error {
	if env == nil {
		return ErrAttestationRequired
	}
	p.mu.RLock()
	var target *PoolMember
	for _, m := range p.members {
		if m.Name == memberName {
			target = m
			break
		}
	}
	knownIssuers := make(map[string]struct{}, len(p.issuers))
	for k := range p.issuers {
		knownIssuers[k] = struct{}{}
	}
	now := p.now()
	p.mu.RUnlock()

	if target == nil {
		return fmt.Errorf("slhdsa-tee: CombinerPool.Attest: unknown member %q", memberName)
	}

	// Drive the chain validation. The Envelope already carries the
	// caller-supplied VerifyOpts (KDSGetter for offline tests,
	// expectedReportData for nonce binding, etc.).
	reports, err := env.VerifyEvidence(ctx)
	if err != nil {
		return fmt.Errorf("slhdsa-tee: CombinerPool.Attest: VerifyEvidence: %w", err)
	}
	if len(reports) != 1 {
		return fmt.Errorf("slhdsa-tee: CombinerPool.Attest: expected exactly one verified report, got %d", len(reports))
	}
	rep := reports[0]
	if _, ok := knownIssuers[rep.Vendor]; !ok {
		return fmt.Errorf("slhdsa-tee: CombinerPool.Attest: vendor %q not in KnownIssuers", rep.Vendor)
	}

	target.mu.Lock()
	target.LastReport = rep
	target.LastIssuedAt = now
	target.mu.Unlock()
	return nil
}

// Combine drives the t-of-n attested-combiner Sign and returns the
// agreed wire bytes + per-member audit signatures.
//
// Flow:
//
//  1. Snapshot the member list under RLock; pick the FIRST Threshold
//     members whose LastIssuedAt + RotationWindow > now. If fewer than
//     Threshold members pass the freshness gate, refuse with
//     ErrMagnetarStaleAttestation.
//  2. For each selected member, drive Signer.Sign with a fresh
//     Envelope holding the most recent attestation evidence (NOT the
//     pool's cached LastReport — Sign requires fresh evidence with
//     the gate-issued nonce; the pool's freshness gate is the
//     additional discipline beyond the per-call attestation).
//  3. Compare the wire bytes byte-for-byte. If all Threshold members
//     produced the same bytes, surface that signature with the audit
//     trail. If they disagree, refuse with
//     ErrMagnetarSignatureDivergence — divergence indicates a
//     misconfigured or compromised combiner; do NOT silently pick.
//
// Each member's Signer call drives the FULL slhdsa-tee.Sign machinery
// (approval, release gate, HSM, magnetar.Sign, audit signature). The
// pool's role is the freshness + t-of-n agreement layer ON TOP of
// each member's per-call discipline.
func (p *CombinerPool) Combine(
	ctx context.Context,
	envs map[string]*Envelope,
	jobID [32]byte,
	msg []byte,
	signCtx []byte,
) ([]byte, []*SignReceipt, error) {
	if len(envs) == 0 {
		return nil, nil, ErrAttestationRequired
	}
	if len(msg) == 0 {
		return nil, nil, errors.New("slhdsa-tee: CombinerPool.Combine: empty message")
	}

	// Snapshot members under RLock so concurrent Attest() doesn't
	// flip the freshness state mid-iteration.
	p.mu.RLock()
	threshold := p.threshold
	rotation := p.rotation
	now := p.now()
	members := make([]*PoolMember, len(p.members))
	copy(members, p.members)
	p.mu.RUnlock()

	if len(members) < threshold {
		return nil, nil, fmt.Errorf("%w: %d members registered, %d required",
			ErrMagnetarInsufficientQuorum, len(members), threshold)
	}

	// Stable iteration order: by name. Tests + audit logs benefit
	// from deterministic member-selection order.
	sort.Slice(members, func(i, j int) bool { return members[i].Name < members[j].Name })

	// Freshness gate: select the first Threshold members whose
	// LastIssuedAt + RotationWindow > now AND whose envelope is
	// present in envs. Any selected member outside the window is a
	// hard refusal — no silent fallback to a stale member.
	type selected struct {
		member *PoolMember
		env    *Envelope
	}
	var sel []selected
	var staleSeen []string
	var missingEvidence []string
	for _, m := range members {
		env, ok := envs[m.Name]
		if !ok {
			missingEvidence = append(missingEvidence, m.Name)
			continue
		}
		m.mu.RLock()
		last := m.LastIssuedAt
		m.mu.RUnlock()
		if last.IsZero() || now.Sub(last) > rotation {
			staleSeen = append(staleSeen, m.Name)
			continue
		}
		sel = append(sel, selected{member: m, env: env})
		if len(sel) >= threshold {
			break
		}
	}

	if len(sel) < threshold {
		// Surface the most actionable refusal:
		//   - if ANY member was stale → ErrMagnetarStaleAttestation
		//   - else → ErrMagnetarInsufficientQuorum
		if len(staleSeen) > 0 {
			return nil, nil, fmt.Errorf("%w: members %v outside rotation window %s (have %d fresh, need %d)",
				ErrMagnetarStaleAttestation, staleSeen, rotation, len(sel), threshold)
		}
		return nil, nil, fmt.Errorf("%w: %d fresh members with evidence, %d required (missing: %v)",
			ErrMagnetarInsufficientQuorum, len(sel), threshold, missingEvidence)
	}

	// Drive each selected member's Sign in series. Parallel would be
	// possible but the audit trail benefits from deterministic
	// member-ordering. (CCF / Hyperledger / Cardano governance
	// patterns all prefer ordered execution under quorum semantics.)
	type signOutput struct {
		wire    []byte
		receipt *SignReceipt
		err     error
		name    string
	}
	out := make([]signOutput, 0, len(sel))
	for _, s := range sel {
		wire, receipt, err := s.member.Signer.Sign(ctx, s.env, jobID, msg, signCtx)
		out = append(out, signOutput{wire: wire, receipt: receipt, err: err, name: s.member.Name})
	}

	// Any per-member failure is a hard refusal at the pool level —
	// the strict-PQ profile cannot silently drop a member from
	// quorum mid-flight.
	for _, o := range out {
		if o.err != nil {
			return nil, nil, fmt.Errorf("slhdsa-tee: CombinerPool.Combine: member %q Sign: %w", o.name, o.err)
		}
	}

	// Byte-equality across the quorum. SLH-DSA SignDeterministic is
	// byte-stable — same (seed, msg, ctx) tuple → identical bytes.
	// Two attested combiners holding the SAME wrapped seed under
	// the SAME RIM MUST produce identical output. Divergence is a
	// hard refusal.
	canonical := out[0].wire
	receipts := make([]*SignReceipt, 0, len(out))
	receipts = append(receipts, out[0].receipt)
	for _, o := range out[1:] {
		if subtle.ConstantTimeCompare(canonical, o.wire) != 1 {
			return nil, nil, fmt.Errorf("%w: %q vs %q", ErrMagnetarSignatureDivergence, out[0].name, o.name)
		}
		receipts = append(receipts, o.receipt)
	}
	return canonical, receipts, nil
}

// Threshold reports the configured t-of-n quorum count. Exposed for
// the dispatcher's documentation surface — embedders that publish
// the pool's policy to audit logs.
func (p *CombinerPool) Threshold() int { return p.threshold }

// RotationWindow reports the configured rotation window. Same
// rationale as Threshold.
func (p *CombinerPool) RotationWindow() time.Duration { return p.rotation }

// MemberCount reports the number of registered members (regardless
// of attestation freshness).
func (p *CombinerPool) MemberCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.members)
}

// FreshMemberCount reports the number of members currently inside
// the rotation window. Useful for control-plane health checks before
// any sign call.
func (p *CombinerPool) FreshMemberCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	now := p.now()
	n := 0
	for _, m := range p.members {
		m.mu.RLock()
		last := m.LastIssuedAt
		m.mu.RUnlock()
		if !last.IsZero() && now.Sub(last) <= p.rotation {
			n++
		}
	}
	return n
}
