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
// reconstructed, and not stored: it is blinded on the device, and what comes
// back is a key derived from it. A register of these evaluations is not a
// password database, because there is nothing in it to hammer.
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

	vcontextString  = "OPRFV1-\x01-" + suite
	vhashToGroupDST = "HashToGroup-" + vcontextString
	vhashToScalarDST = "HashToScalar-" + vcontextString
	vseedDST         = "Seed-" + vcontextString

	// Elements are 32 bytes in this group; the length prefixes below are fixed
	// by that and by the input, not by anything a caller chooses.
	elementSize = 32
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
func Request(rand io.Reader, input []byte) (*Blind, curve.Point, error) {
	h, err := group.HashToPoint([]byte(hashToGroupDST), input)
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

// Combine interpolates t answers back to the single answer the undivided key
// would have given. The domain is the committee the key was shared over, which
// the caller must pass because Lagrange coefficients depend on WHICH parties
// exist, not only on which ones replied.
func Combine(domain []party.ID, answers map[party.ID]curve.Point) (curve.Point, error) {
	if len(answers) == 0 {
		return nil, ErrNoShares
	}
	subset := make([]party.ID, 0, len(answers))
	for id := range answers {
		if !contains(domain, id) {
			return nil, fmt.Errorf("%w: %q", ErrUnknownParty, id)
		}
		subset = append(subset, id)
	}
	// Interpolate over the parties that ANSWERED, not over the whole committee.
	// A Lagrange coefficient is defined by the set of points being interpolated
	// through: λᵢ = Π_{j∈S, j≠i} xⱼ/(xⱼ-xᵢ). Coefficients computed over all n
	// reconstruct only when all n answer, which defeats the threshold — and they
	// fail silently, giving a well-formed element that is not k·B.
	lambda := polynomial.Lagrange(group, subset)

	sum := group.NewPoint()
	for id, answer := range answers {
		sum = sum.Add(lambda[id].Act(answer))
	}
	return sum, nil
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
