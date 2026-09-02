// Package oprf is an oblivious pseudorandom function whose key is held by a
// committee rather than by one server, in the ristretto255-SHA512 suite of
// RFC 9497.
//
// The function is F(k, x) = H(x, k·H(x)). A client learns F(k, x) for the x it
// chose; the key holders learn neither x nor the result. That asymmetry is the
// whole point: a password can be turned into a key that cannot be computed
// offline, because computing it requires the committee, and the committee
// cannot compute it alone because it never sees the input.
//
// What is shared here is the SYSTEM key k — the authority to answer — and never
// a user's password or a hash of one. A password is not secret-shared, not
// reconstructed, and never reaches the committee: it is blinded on the device,
// and what comes back is a key derived from it. No party can learn it, and no
// register of these evaluations is a password file to be cracked.
//
// TWO THINGS THAT CLAIM DOES NOT COVER, both outside this package and both
// required of anything built on it:
//
// The password IS in memory on the device, in Blind, for as long as the caller
// holds one. Blind.Zero wipes it; nothing calls Zero for the caller.
//
// Online guessing is not addressed here and cannot be. A request carries no
// account, by construction — the committee cannot see what was asked, so it
// cannot count attempts against an account, lock one out, or notice that one is
// under attack. Putting the account in the input (x = uid ‖ pw) is necessary
// and not sufficient: the committee must ALSO be given an authenticated account
// label, in the clear, to count against. RFC 9497 §7.2 treats that rate limit
// as a requirement of the password application rather than an optional wrapper.
// And with t parties compromised, k is reconstructed and any stored verifier
// falls to an ordinary offline dictionary attack — the guarantee is that an
// offline attack costs t compromises, not that it is impossible.
//
// Threshold evaluation is Lagrange interpolation in the exponent. With k shared
// as kᵢ, party i answers a blinded element B with kᵢ·B, and a client holding any
// t of those combines Σ λᵢ·(kᵢ·B) = k·B. Nothing about the answer says which
// parties produced it, so the committee can change between evaluations as long
// as the key does not.
//
// TWO MODES, AND THE DIFFERENCE MATTERS. Evaluate/Combine are RFC 9497's plain
// OPRF: a party that returns a wrong element is NOT detected, and the client
// derives a wrong key it cannot tell from having been given the wrong password.
// Combine's success is not evidence that the parties behaved.
//
// EvaluateVerifiable/CombineVerified (proof.go) carry a per-evaluation DLEQ
// proof, so a wrong element is refused by name. Use those wherever the
// committee is not uniformly trusted — which, for a committee, is the point.
package oprf

import (
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/party"
)

// The suite. contextString is "OPRFV1-" ‖ I2OSP(mode,1) ‖ "-" ‖ identifier with
// mode 0x00 for OPRF, and every domain tag hangs off it, so a deployment of a
// different mode or suite cannot be confused with this one.
const (
	suite    = "ristretto255-SHA512"
	modeOPRF = 0x00
	// modeVOPRF is the VERIFIABLE mode. It is a different byte in the context
	// string, so every domain tag below differs from the plain mode's — an
	// evaluation in one mode can never be replayed as the other, which is the
	// point of the mode being in the string at all.
	modeVOPRF = 0x01

	contextString  = "OPRFV1-\x00-" + suite
	hashToGroupDST = "HashToGroup-" + contextString

	vcontextString   = "OPRFV1-\x01-" + suite
	vhashToGroupDST  = "HashToGroup-" + vcontextString
	vhashToScalarDST = "HashToScalar-" + vcontextString
	vseedDST         = "Seed-" + vcontextString

	// A scalar is 32 bytes in this group.
	scalarSize = 32
)

var group = curve.Ristretto255{}

var (
	// ErrNoShares is returned when a combination is asked for with nothing to combine.
	ErrNoShares = errors.New("oprf: no shares to combine")
	// ErrUnknownParty is returned when a share names a party outside the committee.
	ErrUnknownParty = errors.New("oprf: share from a party outside the interpolation domain")
	// ErrIdentity is returned when a blinded element is the identity, which
	// carries no information about the input and would evaluate to a constant.
	ErrIdentity = errors.New("oprf: element is the identity")
	// ErrInput is returned for an input longer than its two-byte length prefix
	// can state. Every value the transcript hashes carries one, and the input is
	// the only one whose length a caller chooses.
	ErrInput = errors.New("oprf: input longer than its length prefix can state")
	// ErrWrongKey is returned when the public shares that the proofs verified
	// against do not interpolate to the key the evaluation was asked for.
	ErrWrongKey = errors.New("oprf: public shares do not belong to this key")
)

// Key is one party's share of the committee's key — of the authority to answer,
// not of anybody's password. Holding every share would reveal k and let its
// holder compute F(k, ·) offline for guessed inputs; that is why the shares are
// separated, and it is the only secret in the scheme.
type Key struct {
	Party party.ID
	Share curve.Scalar
	// Public is this share on the generator, kᵢ·G. It is what a client checks a
	// proof against, so it is public by construction and carrying it here keeps
	// the pair together — a share whose commitment lives somewhere else is a
	// share nobody can be held to.
	Public curve.Point
}

// Blind is what a client keeps between sending a request and reading the
// answer. It is the only value that must not leave the device: with it the
// answer unblinds to the key, without it the answer is a random group element.
type Blind struct {
	r     curve.Scalar
	input []byte
}

// Request blinds an input for evaluation. The returned element is what travels;
// it is uniform in the group and independent of the input, so a party that sees
// every request learns nothing about what was asked.
//
// This is the PLAIN mode. Pair it with Evaluate and Combine; for the mode whose
// answers carry a proof, use RequestVerifiable.
func Request(rand io.Reader, input []byte) (*Blind, curve.Point, error) {
	return request(rand, input, hashToGroupDST)
}

// RequestVerifiable blinds an input for the VERIFIABLE evaluation — the mode
// EvaluateVerifiable answers and CombineVerified checks.
//
// It exists because the mode is in the domain tag. The two modes hash an input
// to different points, so blinding here and proving there would leave one
// evaluation carrying two modes: not the protocol the RFC defines, and not one
// any conformant peer computes the same way. RFC 9497 A.1.2.1 blinds 0x00 to
// 863f330c… under this tag and A.1.1.1 blinds it to 609a0ae6… under the other,
// which is the whole difference and is what the vector tests pin.
func RequestVerifiable(rand io.Reader, input []byte) (*Blind, curve.Point, error) {
	return request(rand, input, vhashToGroupDST)
}

func request(rand io.Reader, input []byte, dst string) (*Blind, curve.Point, error) {
	// Bounded here, once, rather than at each prefix: the input is the only
	// value the transcript hashes whose length a caller chooses, and a Blind
	// keeps a copy of exactly this, so Finalize's prefixes are in range too.
	if len(input) > 1<<16-1 {
		return nil, nil, ErrInput
	}
	h, err := group.HashToPoint([]byte(dst), input)
	if err != nil {
		return nil, nil, fmt.Errorf("oprf: hash to group: %w", err)
	}
	if h.IsIdentity() {
		// H maps to the identity with negligible probability; if it ever does,
		// the evaluation would be a constant, so refuse rather than answer it.
		return nil, nil, ErrIdentity
	}
	r := sampleNonZero(rand)
	return &Blind{r: r, input: append([]byte{}, input...)}, r.Act(h), nil
}

// Evaluate is one party's answer: its share applied to the blinded element. It
// is a scalar multiplication and nothing else — the party has no way to learn
// the input, and no state to keep between requests.
func Evaluate(k Key, blinded curve.Point) (curve.Point, error) {
	if blinded.IsIdentity() {
		return nil, ErrIdentity
	}
	return k.Share.Act(blinded), nil
}

// coefficients are the interpolation weights for the parties that ANSWERED,
// which is the only set they may be computed over. A Lagrange coefficient is
// defined by the points being interpolated through: λᵢ = Π_{j∈S, j≠i} xⱼ/(xⱼ-xᵢ).
// Computed over all n they reconstruct only when all n answer, which defeats
// the threshold — and they fail silently, giving a well-formed element that is
// not k·B.
//
// domain is a membership list and nothing more: it says which ids the committee
// admits, and does not enter the arithmetic.
func coefficients(domain []party.ID, ids []party.ID) (map[party.ID]curve.Scalar, error) {
	subset := make([]party.ID, 0, len(ids))
	for _, id := range ids {
		if !contains(domain, id) {
			return nil, fmt.Errorf("%w: %q", ErrUnknownParty, id)
		}
		subset = append(subset, id)
	}
	return polynomial.Lagrange(group, subset), nil
}

func answered[T any](m map[party.ID]T) []party.ID {
	ids := make([]party.ID, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	return ids
}

// Combine interpolates t answers back to the single answer the undivided key
// would have given. domain is the committee the key was shared over, and is
// used to refuse an id the committee does not admit.
func Combine(domain []party.ID, answers map[party.ID]curve.Point) (curve.Point, error) {
	if len(answers) == 0 {
		return nil, ErrNoShares
	}
	lambda, err := coefficients(domain, answered(answers))
	if err != nil {
		return nil, err
	}

	sum := group.NewPoint()
	for id, answer := range answers {
		sum = sum.Add(lambda[id].Act(answer))
	}
	return sum, nil
}

// Zero wipes the password and the blind. A Blind is deliberately reusable —
// Finalize does not consume it, because one evaluation is often finalized more
// than once — so nothing can wipe it on the caller's behalf, and the input sits
// in memory until this is called. It is the caller's last step, not an optional
// one: everything else in this package is about the password never leaving the
// device, and this is what bounds how long it stays on it.
func (b *Blind) Zero() {
	for i := range b.input {
		b.input[i] = 0
	}
	b.input = nil
	if b.r != nil {
		b.r.Set(group.NewScalar())
	}
}

// Finalize unblinds the combined answer and derives the output, which is the
// value a caller uses as a key. The input is bound into the hash alongside the
// element, so two different inputs cannot produce the same output even if a
// party could steer the element.
func (b *Blind) Finalize(combined curve.Point) ([]byte, error) {
	if combined.IsIdentity() {
		return nil, ErrIdentity
	}
	// Copy before inverting: Invert mutates the receiver, and b.r has to survive
	// so a Blind can be finalized more than once.
	inv := group.NewScalar().Set(b.r).Invert()
	unblinded := inv.Act(combined)
	raw, err := unblinded.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("oprf: serialize element: %w", err)
	}

	h := sha512.New()
	writeWithLength(h, b.input)
	writeWithLength(h, raw)
	h.Write([]byte("Finalize"))
	return h.Sum(nil), nil
}

// Evaluate with an undivided key, which is what the committee's shares
// reconstruct. Kept because it is the definition the threshold path must agree
// with, and a test that cannot state the single-key answer cannot show that the
// shared one matches it.
func EvaluateWhole(k curve.Scalar, blinded curve.Point) curve.Point {
	return k.Act(blinded)
}

// writeWithLength emits I2OSP(len(b), 2) ‖ b. The prefix is what stops two
// different (input, element) pairs from hashing the same bytes.
func writeWithLength(h io.Writer, b []byte) {
	var n [2]byte
	binary.BigEndian.PutUint16(n[:], uint16(len(b)))
	_, _ = h.Write(n[:])
	_, _ = h.Write(b)
}

func sampleNonZero(rand io.Reader) curve.Scalar {
	for {
		s := sample(rand)
		if !s.IsZero() {
			return s
		}
	}
}

func sample(rand io.Reader) curve.Scalar {
	var buf [64]byte
	if _, err := io.ReadFull(rand, buf[:]); err != nil {
		panic(fmt.Sprintf("oprf: read randomness: %v", err))
	}
	return curve.FromHash(group, buf[:])
}

func contains(ids []party.ID, id party.ID) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}
