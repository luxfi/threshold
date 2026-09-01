package oprf

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/party"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

// scalarFrom reads a scalar written the way RFC 9497 writes one.
//
// The RFC — and ristretto255 generally — encodes scalars LITTLE-endian. This
// repo's Ristretto255Scalar codec is big-endian, so the bytes must be reversed
// on the way in. That difference is invisible in normal use, because a scalar
// here never crosses a wire: the blind stays on the device and only ELEMENTS
// travel, and those the repo already writes in ristretto's canonical encoding,
// which is why the element and output comparisons below need no such handling.
func scalarFrom(t *testing.T, hexStr string) curve.Scalar {
	t.Helper()
	le := mustHex(t, hexStr)
	be := make([]byte, len(le))
	for i := range le {
		be[i] = le[len(le)-1-i]
	}
	s := group.NewScalar()
	if err := s.UnmarshalBinary(be); err != nil {
		t.Fatalf("scalar %q: %v", hexStr, err)
	}
	return s
}

func pointFrom(t *testing.T, hexStr string) curve.Point {
	t.Helper()
	p := group.NewPoint()
	if err := p.UnmarshalBinary(mustHex(t, hexStr)); err != nil {
		t.Fatalf("point %q: %v", hexStr, err)
	}
	return p
}

// RFC 9497 A.1.1.1, the first OPRF-mode vector for ristretto255-SHA512.
//
// This is the test that decides whether the construction is the one the RFC
// defines rather than merely a self-consistent one of my own. Every part is
// pinned: the hash-to-group map, the blinding, the evaluation, and the exact
// bytes Finalize hashes. A scheme that round-trips perfectly and disagrees here
// would interoperate with nothing and would have security nobody has analysed.
const (
	vecSkSm             = "5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e"
	vecInput            = "00"
	vecBlind            = "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"
	vecBlindedElement   = "609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c"
	vecEvaluatedElement = "7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e"
	vecOutput           = "527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3" +
		"ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6"
)

func TestRFC9497Vector(t *testing.T) {
	input := mustHex(t, vecInput)
	blind := scalarFrom(t, vecBlind)

	// Blinding, with the vector's blind rather than a fresh one.
	h, err := group.HashToPoint([]byte(hashToGroupDST), input)
	if err != nil {
		t.Fatalf("hash to group: %v", err)
	}
	blinded := blind.Act(h)
	got, err := blinded.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want := mustHex(t, vecBlindedElement); !bytes.Equal(got, want) {
		t.Fatalf("blinded element\n got %x\nwant %x", got, want)
	}

	// Evaluation with the undivided key.
	evaluated := EvaluateWhole(scalarFrom(t, vecSkSm), blinded)
	got, err = evaluated.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want := mustHex(t, vecEvaluatedElement); !bytes.Equal(got, want) {
		t.Fatalf("evaluated element\n got %x\nwant %x", got, want)
	}

	// Unblinding and the output hash.
	out, err := (&Blind{r: blind, input: input}).Finalize(evaluated)
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if want := mustHex(t, vecOutput); !bytes.Equal(out, want) {
		t.Fatalf("output\n got %x\nwant %x", out, want)
	}
}

// share splits k over `domain` with threshold t, and returns each party's Key.
func share(t *testing.T, k curve.Scalar, domain []party.ID, degree int) map[party.ID]Key {
	t.Helper()
	poly := polynomial.NewPolynomial(group, degree, k)
	out := make(map[party.ID]Key, len(domain))
	for _, id := range domain {
		out[id] = Key{Party: id, Share: poly.Evaluate(id.Scalar(group))}
	}
	return out
}

// The property that makes this a THRESHOLD OPRF rather than n independent ones:
// any qualifying subset reproduces the answer the undivided key would give, and
// therefore the same output — so which parties answered is invisible to the
// client and to anyone reading the result.
func TestAnyQualifyingSubsetGivesTheUndividedAnswer(t *testing.T) {
	domain := []party.ID{"a", "b", "c", "d", "e"}
	const degree = 2 // t-of-n with t = degree+1 = 3

	k := sample(rand.Reader)
	keys := share(t, k, domain, degree)

	blind, blinded, err := Request(rand.Reader, []byte("correct horse battery staple"))
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	// What the undivided key would have answered.
	want, err := blind.Finalize(EvaluateWhole(k, blinded))
	if err != nil {
		t.Fatalf("finalize whole: %v", err)
	}

	subsets := [][]party.ID{
		{"a", "b", "c"},
		{"c", "d", "e"},
		{"a", "c", "e"},
		{"a", "b", "c", "d", "e"},
	}
	for _, subset := range subsets {
		answers := make(map[party.ID]curve.Point, len(subset))
		for _, id := range subset {
			ans, err := Evaluate(keys[id], blinded)
			if err != nil {
				t.Fatalf("evaluate %s: %v", id, err)
			}
			answers[id] = ans
		}
		combined, err := Combine(domain, answers)
		if err != nil {
			t.Fatalf("combine %v: %v", subset, err)
		}
		got, err := blind.Finalize(combined)
		if err != nil {
			t.Fatalf("finalize %v: %v", subset, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("subset %v disagreed with the undivided key\n got %x\nwant %x", subset, got, want)
		}
	}
}

// And the other half of "threshold": too few shares must NOT reproduce it.
// Without this the test above would pass against a scheme that ignored the
// shares entirely.
func TestTooFewSharesDoNotReconstruct(t *testing.T) {
	domain := []party.ID{"a", "b", "c", "d", "e"}
	const degree = 2

	k := sample(rand.Reader)
	keys := share(t, k, domain, degree)

	blind, blinded, err := Request(rand.Reader, []byte("correct horse battery staple"))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	want, err := blind.Finalize(EvaluateWhole(k, blinded))
	if err != nil {
		t.Fatalf("finalize whole: %v", err)
	}

	for _, subset := range [][]party.ID{{"a"}, {"a", "b"}, {"d", "e"}} {
		answers := make(map[party.ID]curve.Point, len(subset))
		for _, id := range subset {
			ans, _ := Evaluate(keys[id], blinded)
			answers[id] = ans
		}
		combined, err := Combine(domain, answers)
		if err != nil {
			t.Fatalf("combine %v: %v", subset, err)
		}
		got, err := blind.Finalize(combined)
		if err != nil {
			t.Fatalf("finalize %v: %v", subset, err)
		}
		if bytes.Equal(got, want) {
			t.Fatalf("subset %v of size %d reconstructed the key below the threshold", subset, len(subset))
		}
	}
}

// The committee never sees the input, and what travels carries no trace of it.
// Two requests for the SAME input must look unrelated on the wire, or a party
// could tell that a user retried the same password.
func TestBlindedElementRevealsNothingAboutTheInput(t *testing.T) {
	input := []byte("hunter2")
	_, first, err := Request(rand.Reader, input)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_, second, err := Request(rand.Reader, input)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	a, _ := first.MarshalBinary()
	b, _ := second.MarshalBinary()
	if bytes.Equal(a, b) {
		t.Fatal("two requests for the same input produced the same element; a party could link them")
	}
}

// A Blind must survive being finalized, because a caller may combine more than
// one subset. Invert mutates its receiver, so this is a real hazard rather than
// a hypothetical one.
func TestFinalizeDoesNotConsumeTheBlind(t *testing.T) {
	k := sample(rand.Reader)
	blind, blinded, err := Request(rand.Reader, []byte("x"))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	evaluated := EvaluateWhole(k, blinded)

	first, err := blind.Finalize(evaluated)
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	second, err := blind.Finalize(evaluated)
	if err != nil {
		t.Fatalf("second finalize: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("finalizing twice gave different answers; the blind was consumed")
	}
}

// A share from outside the committee has no Lagrange coefficient, so combining
// it would silently produce a wrong key. Refuse it by name instead.
func TestAnswerFromOutsideTheCommitteeIsRefused(t *testing.T) {
	domain := []party.ID{"a", "b", "c"}
	_, blinded, err := Request(rand.Reader, []byte("x"))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_, err = Combine(domain, map[party.ID]curve.Point{"stranger": blinded})
	if err == nil {
		t.Fatal("a share from outside the interpolation domain was accepted")
	}
}

// RFC 9497 A.1.2.1 — the VOPRF-mode vector. Its BlindedElement differs from the
// OPRF-mode one above for the same input and the same blind, because the mode
// byte is in the domain tag. That difference is the reason the verifiable flow
// needs its own constructor: an evaluation blinded here and proven under the
// other tag is neither of the two protocols the RFC defines.
func TestRFC9497VerifiableBlindMatchesItsOwnMode(t *testing.T) {
	input := mustHex(t, vInput)

	// The vector pins the map: under the VOPRF tag this input and this blind
	// give this element.
	h, err := group.HashToPoint([]byte(vhashToGroupDST), input)
	if err != nil {
		t.Fatalf("hash to group: %v", err)
	}
	got, err := scalarFrom(t, vBlind).Act(h).MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want := mustHex(t, vBlinded); !bytes.Equal(got, want) {
		t.Fatalf("verifiable blinded element\n got %x\nwant %x", got, want)
	}

	// And RequestVerifiable is the function that uses it. Its own blind is
	// fresh, so the element is compared against that blind acting on the map
	// above — which fails if it reached for the plain mode's tag instead.
	b, el, err := RequestVerifiable(rand.Reader, input)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if want := b.r.Act(h); !el.Equal(want) {
		t.Fatal("RequestVerifiable did not blind under the verifiable mode's tag")
	}

	// Request is the other mode and must not agree, or the tag separates nothing.
	pb, pel, err := Request(rand.Reader, input)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if pel.Equal(pb.r.Act(h)) {
		t.Fatal("Request blinded under the verifiable tag; the modes are not separated")
	}
}

// The package's claim is that a password never reaches the committee. It does
// reach memory on the device, and stays there as long as a Blind does, because
// a Blind is reusable and so nothing can wipe it on the caller's behalf.
func TestZeroWipesThePasswordAndTheBlind(t *testing.T) {
	pw := []byte("correct horse battery staple")
	b, _, err := RequestVerifiable(rand.Reader, pw)
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	// Request copies the input, so the caller's slice is not the one held.
	if &b.input[0] == &pw[0] {
		t.Fatal("Blind aliases the caller's password rather than copying it")
	}
	if !bytes.Equal(b.input, pw) {
		t.Fatal("Blind does not hold the password it was given")
	}
	held := b.input // the same backing array Zero must clear

	b.Zero()

	if bytes.Contains(held, []byte("horse")) {
		t.Error("the password is still in the buffer the Blind held")
	}
	for _, c := range held {
		if c != 0 {
			t.Fatalf("the buffer was not wiped: %x", held)
		}
	}
	if !b.r.Equal(group.NewScalar()) {
		t.Error("the blind scalar survived Zero; with it an answer still unblinds")
	}
	if !bytes.Equal(pw, []byte("correct horse battery staple")) {
		t.Error("Zero reached through into the caller's own slice")
	}
}
