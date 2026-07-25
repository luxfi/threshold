// Package quorum expresses a threshold-signing policy as the value operators
// actually reason about: k signers out of n parties — "3-of-5".
//
// # Why this package exists
//
// The threshold protocols in this module (CGGMP21 in protocols/cmp, FROST in
// protocols/frost) are both parameterised by t, the number of corruptions
// tolerated. Both require t+1 shares to produce a signature. Operators,
// dashboards, runbooks and Safe policies instead speak in k-of-n, where k is
// the number of signers that must cooperate.
//
// Those are two different numbers for the same policy, and the off-by-one
// between them is silent: provisioning a "3-of-5" wallet by passing
// threshold=3, parties=5 to a protocol that reads threshold as t produces a
// 4-of-5 wallet. Nothing errors. The mistake only surfaces when three
// custodians hold a signing ceremony and cannot produce a signature — which,
// for a key that already controls funds, is an outage with no recovery path
// short of a resharing ceremony with a party that may no longer exist.
//
// Policy is therefore the single place k and t are allowed to meet. Callers
// state the policy they mean (k-of-n) and hand [Policy.Degree] to the
// protocol. Nothing else in the stack should compute k-1 or t+1 by hand.
package quorum

import (
	"fmt"
	"strconv"
	"strings"
)

// Policy is a signing policy: K signers, drawn from N parties, are required
// and sufficient to produce one signature.
//
// The zero Policy is not valid; construct with [New] or [Parse].
type Policy struct {
	// K is the number of parties that must cooperate to sign.
	K int
	// N is the total number of parties holding a share.
	N int
}

// New returns the k-of-n policy, or an error explaining why it is not a
// policy anyone should deploy.
//
// k == 1 is rejected: a 1-of-n key is a single key with n copies of the
// secret-recovery capability, which is strictly worse than one key, not
// better. Callers that genuinely want single-party signing should use a
// single-party signer rather than a degenerate threshold configuration.
func New(k, n int) (Policy, error) {
	switch {
	case n < 2:
		return Policy{}, fmt.Errorf("quorum: n = %d, want at least 2 parties", n)
	case k < 2:
		return Policy{}, fmt.Errorf("quorum: k = %d, want at least 2 signers (k=1 is not a threshold policy)", k)
	case k > n:
		return Policy{}, fmt.Errorf("quorum: k = %d exceeds n = %d; the policy could never be satisfied", k, n)
	}
	return Policy{K: k, N: n}, nil
}

// MustNew is [New] for policies fixed at compile time. It panics on an
// invalid policy.
func MustNew(k, n int) Policy {
	p, err := New(k, n)
	if err != nil {
		panic(err)
	}
	return p
}

// Degree returns t, the polynomial degree and corruption bound the underlying
// protocols are parameterised by. It is the value to pass as the `threshold`
// argument of cmp.Keygen and frost.Keygen, and the value stored in
// cmp/config.Config.Threshold and frost/keygen.Config.Threshold.
//
// t = K-1: any K shares reconstruct, any t = K-1 do not.
func (p Policy) Degree() int { return p.K - 1 }

// Tolerance returns how many of the N parties may be unavailable while the
// policy can still be satisfied: N-K.
//
// Note that this is availability, not security. The security bound — how many
// parties may be actively corrupted without forging a signature — is
// [Policy.Degree]. For 3-of-5 those coincide at 2; for 4-of-5 they do not
// (tolerance 1, corruption bound 3).
func (p Policy) Tolerance() int { return p.N - p.K }

// Valid reports whether p is a deployable policy.
func (p Policy) Valid() bool {
	_, err := New(p.K, p.N)
	return err == nil
}

// String renders the policy the way operators write it: "3-of-5".
func (p Policy) String() string { return strconv.Itoa(p.K) + "-of-" + strconv.Itoa(p.N) }

// FromDegree reconstructs the policy of a key already generated with
// polynomial degree t shared among n parties — the inverse of [Policy.Degree],
// for reading back an existing cmp or frost config.
func FromDegree(t, n int) (Policy, error) {
	return New(t+1, n)
}

// MarshalText renders the policy in operator form so that any config, genesis
// blob or API payload carrying a Policy is self-describing: "3-of-5" cannot be
// misread as a degree, whereas a bare `"threshold": 3` can and has been.
//
// Policy implements encoding.TextMarshaler/TextUnmarshaler rather than a JSON
// codec so the same single representation works for JSON, YAML, TOML, flags and
// map keys — one form everywhere.
func (p Policy) MarshalText() ([]byte, error) {
	if !p.Valid() {
		return nil, fmt.Errorf("quorum: refusing to encode invalid policy %d-of-%d", p.K, p.N)
	}
	return []byte(p.String()), nil
}

// UnmarshalText reads the operator form. An absent or malformed policy is an
// error, never a silent zero value: a Policy that decoded to {0,0} would be
// indistinguishable from "unset" at the keygen boundary, and the failure mode
// of guessing there is an unrecoverable wrong-degree key.
func (p *Policy) UnmarshalText(text []byte) error {
	parsed, err := Parse(string(text))
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}

// Parse reads the operator form, "3-of-5". It accepts surrounding space and
// an "of" separator with or without hyphens ("3 of 5"), because those are the
// forms that show up in runbooks and dashboards.
func Parse(s string) (Policy, error) {
	norm := strings.ToLower(strings.TrimSpace(s))
	norm = strings.ReplaceAll(norm, "-", " ")
	fields := strings.Fields(norm)
	if len(fields) != 3 || fields[1] != "of" {
		return Policy{}, fmt.Errorf("quorum: cannot parse %q, want the form \"3-of-5\"", s)
	}
	k, err := strconv.Atoi(fields[0])
	if err != nil {
		return Policy{}, fmt.Errorf("quorum: cannot parse %q: bad signer count %q", s, fields[0])
	}
	n, err := strconv.Atoi(fields[2])
	if err != nil {
		return Policy{}, fmt.Errorf("quorum: cannot parse %q: bad party count %q", s, fields[2])
	}
	return New(k, n)
}
