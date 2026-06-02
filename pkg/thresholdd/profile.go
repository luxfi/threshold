// SPDX-License-Identifier: BSD-3-Clause
package thresholdd

import (
	"errors"
)

// profile.go — chain-profile gate.
//
// One function, one place. The gate (RefuseUnderStrictPQ) is the
// single policy boundary the dispatcher consults to decide whether
// the single-party dealer shortcut on Sign_Ctx is acceptable on this
// chain. Everything upstream just calls RefuseUnderStrictPQ at the
// top of the relevant operation and otherwise stays in its lane —
// no policy-mixing, no per-scheme gate forks.
//
// Why this lives here (and not on the embedder side):
//
//   - doc.go's "this package contains zero policy" note still holds
//     for routing / auth / audit / per-method admission. The
//     strict-PQ vs single-party-shortcut decision IS NOT routing
//     policy — it is a primitive-soundness guard tightly coupled to
//     pulsar v0.3's documented limitation (empty-ctx-only) and
//     magnetar's single-validator-shortcut on Sign_Ctx. Refusing
//     these under strict-PQ has to happen at the call site that
//     produces the signature, not at an outer routing layer that
//     does not know which signing path the dispatcher chose.
//
// Why this is a thin abstraction (not a registry import):
//
//   - luxfi/threshold MUST NOT pick up a dependency on
//     luxfi/consensus/config (that module pulls validators, FPC,
//     bridge profile, etc. — far more than this gate needs and a
//     painful cascade on every consensus bump). Instead we expose a
//     tiny ChainProfileResolver interface; the embedder (luxfi/mpc
//     or luxfi/node) supplies an adapter that calls
//     config.ProfileByID under the hood.
//
// Boundary contract:
//
//   - StrictPQ profile: NO single-party dealer/single-validator
//     shortcut on Sign_Ctx (or any other path that would surface a
//     bit-equal classical-shape signature without an actual
//     threshold-bound ctx). Gate RETURNS HTTP 503 + the documented
//     body so the caller knows the operation is temporarily refused
//     pending sister-agent's pulsar v0.4 ctx-bound path landing.
//   - LegacyCompat / Permissive profile: shortcuts acceptable as
//     documented dev-tooling. Operators are responsible for not
//     building production on top of permissive profiles.
//   - Unknown profile (no resolver wired OR resolver returned no
//     match): fail-OPEN. The dispatcher predates strict-PQ
//     deployment and a missing resolver would otherwise refuse
//     every Sign_Ctx call ever made. Documented in
//     RefuseUnderStrictPQ — embedders that want fail-closed wire
//     their own outer admission gate.
//
// Removal:
//
//   - Once sister agent's pulsar v1.1.0 (v0.4 ctx-bound) ships AND
//     pulsar.go::Sign_Ctx swaps to OrchestrateV03SignCtx (the
//     proper threshold ctx-bound path with NO dealerKey), this gate
//     becomes a no-op for the pulsar single-party-shortcut path.
//     Likewise the magnetar gate vanishes when magnetar Sign_Ctx
//     drives a per-validator standalone aggregate-cert path that
//     binds ctx into the N-of-N aggregation instead of routing
//     through keys[0]. At that point RefuseUnderStrictPQ stops
//     being load-bearing on those call sites — but the function
//     stays as the documented audit hook for any future
//     primitive-soundness gate on strict-PQ chains. (One function,
//     one place — outliving any particular bug.)

// Profile is the chain-wide security-class label this dispatcher
// reasons about. Three buckets are enough — the consensus toolkit
// distinguishes finer (StrictPQ / Permissive / FIPS), but the
// dispatcher only needs "is this strict-PQ?" to fire the gate.
type Profile uint8

const (
	// ProfileUnknown means no resolver returned a profile for the
	// chain ID (or no resolver was wired). The gate fails OPEN under
	// this profile — see package doc for the rationale.
	ProfileUnknown Profile = 0

	// ProfileStrictPQ corresponds to luxfi/consensus/config
	// ProfileStrictPQ (0x01) AND ProfileFIPS (0x03) — the profiles
	// whose IsPQ() returns true. Either profile demands a refusal
	// here because both forbid the single-party dealer shortcut on
	// any classical-shape primitive.
	ProfileStrictPQ Profile = 1

	// ProfileLegacyCompat covers permissive and any non-strict-PQ
	// profile that explicitly accepts dealer-derived shortcuts (the
	// dispatcher's documented dev-tooling role). Gate lets the call
	// through.
	ProfileLegacyCompat Profile = 2
)

// String returns the canonical lowercase profile name (mirrors
// luxfi/consensus/config.ProfileID.String).
func (p Profile) String() string {
	switch p {
	case ProfileStrictPQ:
		return "strict-PQ"
	case ProfileLegacyCompat:
		return "legacy-compat"
	default:
		return "unknown"
	}
}

// ChainProfileResolver maps a chain ID (the X-Chain-ID HTTP header
// or the optional ChainID field on signCtxParams) to the chain's
// active Profile. The resolver lives on the embedder side so this
// package does not import luxfi/consensus/config; luxfi/mpc and
// luxfi/node each wire their own resolver from genesis manifest /
// runtime profile state.
//
// Implementations MUST be safe for concurrent use. Returning
// ProfileUnknown for an unrecognised chainID is the documented
// fail-OPEN signal.
type ChainProfileResolver interface {
	ResolveChainProfile(chainID string) Profile
}

// staticResolver is a tiny in-process resolver useful for tests and
// for the standalone thresholdd CLI (which pins one profile for the
// whole process lifetime). Production embedders supply their own
// implementation.
type staticResolver struct {
	chains map[string]Profile
	def    Profile
}

// NewStaticChainProfileResolver builds a static resolver. chainID
// keys not in the map fall back to def. Pass def=ProfileUnknown to
// fail-OPEN for unknown chains; pass def=ProfileStrictPQ on a
// PQ-only deployment so missing entries default-refuse.
func NewStaticChainProfileResolver(def Profile, chains map[string]Profile) ChainProfileResolver {
	cp := make(map[string]Profile, len(chains))
	for k, v := range chains {
		cp[k] = v
	}
	return &staticResolver{chains: cp, def: def}
}

func (r *staticResolver) ResolveChainProfile(chainID string) Profile {
	if p, ok := r.chains[chainID]; ok {
		return p
	}
	return r.def
}

// IsStrictPQProfile reports whether chainID maps to ProfileStrictPQ
// via the supplied resolver. Returns false when resolver is nil or
// the resolver returns any non-strict-PQ profile.
//
// This is the single-source-of-truth lookup; call sites that need
// the gate go through RefuseUnderStrictPQ which calls this under
// the hood.
func IsStrictPQProfile(chainID string, resolver ChainProfileResolver) bool {
	if resolver == nil {
		return false
	}
	return resolver.ResolveChainProfile(chainID) == ProfileStrictPQ
}

// ErrRefusedUnderStrictPQ is the sentinel returned by
// RefuseUnderStrictPQ when the operation is refused on a strict-PQ
// chain. The HTTP layer maps this to a 503 with the documented
// body; in-process callers may inspect it with errors.Is.
var ErrRefusedUnderStrictPQ = errors.New("operation refused on strict-PQ chain profile")

// strictPQRefusalBody is the documented JSON-RPC body the dispatcher
// returns alongside HTTP 503 when the strict-PQ gate fires. Pinned
// here so server.go and tests share one canonical string.
const strictPQRefusalBody = `{"error": "Sign_Ctx requires pulsar v0.4 threshold ctx-bound path; rejected on strict-PQ chain profile"}`

// RefuseUnderStrictPQ is THE single policy gate. Call sites that
// surface a single-party dealer / single-validator shortcut on a
// classical-shape ctx-bound primitive call this at entry; the
// function returns ErrRefusedUnderStrictPQ when the chain is on
// strict-PQ and nil otherwise.
//
// Decomplecting note: every dispatcher method that could possibly
// be refused on strict-PQ calls this ONE function exactly once at
// the top. Verification / authorisation / audit logic does NOT
// braid into the gate — they stay in their lanes. Mirrors the
// classical-precompile profile gate
// (luxfi/precompile/contract.RefuseUnderStrictPQ) so the project
// has one obvious way to express "refuse on strict-PQ".
//
// op is the human-readable operation tag (e.g. "pulsar.sign_ctx",
// "magnetar.sign_ctx"). Surfaced in the error message so audit
// logs name exactly which method tripped the gate.
//
// Returns nil — gate passes — when:
//
//   - resolver is nil (no chain-profile resolver wired; documented
//     fail-OPEN for backward compatibility), OR
//   - chainID is empty (caller did not assert a chain; treat as
//     "no chain context, no strict-PQ posture to enforce"), OR
//   - resolver returns a non-strict-PQ profile.
//
// Returns ErrRefusedUnderStrictPQ wrapped with op + chainID when
// the chain is on ProfileStrictPQ. The wrapped message MUST stay
// stable so audit-log parsing downstream does not break.
func RefuseUnderStrictPQ(chainID, op string, resolver ChainProfileResolver) error {
	if resolver == nil || chainID == "" {
		return nil
	}
	if resolver.ResolveChainProfile(chainID) != ProfileStrictPQ {
		return nil
	}
	return errors.Join(ErrRefusedUnderStrictPQ,
		errors.New(op+" refused: chain "+chainID+" is on strict-PQ profile; "+
			"pulsar v0.4 threshold ctx-bound path required (see doc.go)"))
}
