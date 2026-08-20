package reveal

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/math/sample"
	"github.com/luxfi/threshold/pkg/party"
)

// group is one share set, dealt the way a DKG deals one: a random secret split
// by a degree-t polynomial, with each party's commitment published.
type shareSet struct {
	group        curve.Curve
	threshold    int
	ids          []party.ID
	shares       map[party.ID]curve.Scalar
	public       curve.Point
	verification *party.PointMap
}

func deal(t *testing.T, n, threshold int) *shareSet {
	t.Helper()
	g := curve.Secp256k1{}

	f := polynomial.NewPolynomial(g, threshold, sample.Scalar(rand.Reader, g))
	s := &shareSet{
		group:     g,
		threshold: threshold,
		shares:    map[party.ID]curve.Scalar{},
		public:    f.Constant().ActOnBase(),
	}
	points := map[party.ID]curve.Point{}
	for i := 1; i <= n; i++ {
		id := party.ID(string(rune('a' + i - 1)))
		share := f.Evaluate(id.Scalar(g))
		s.ids = append(s.ids, id)
		s.shares[id] = share
		points[id] = share.ActOnBase()
	}
	s.verification = party.NewPointMap(points)
	return s
}

func (s *shareSet) answer(t *testing.T, ct *Ciphertext, ids ...party.ID) []*Answer {
	t.Helper()
	var out []*Answer
	for _, id := range ids {
		a, err := ct.Answer(rand.Reader, id, s.shares[id])
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

// The round trip. t+1 of five parties open what the group was sealed to.
func TestEnoughPartiesOpenIt(t *testing.T) {
	s := deal(t, 5, 2)
	want := []byte("the thirty-two byte root this protects")

	ct, err := Encrypt(rand.Reader, s.public, want)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct.Body, want) {
		t.Fatal("the message is present in the ciphertext")
	}

	got, err := Open(ct, s.threshold, s.verification, s.answer(t, ct, "a", "b", "c"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("opened %q, want %q", got, want)
	}
}

// ANY t+1 open it, and they all reach the same message. A threshold that only
// worked for the first t+1 parties would not be a threshold.
func TestAnyEnoughPartiesReachTheSameMessage(t *testing.T) {
	s := deal(t, 5, 2)
	want := []byte("one secret")
	ct, err := Encrypt(rand.Reader, s.public, want)
	if err != nil {
		t.Fatal(err)
	}

	for _, set := range [][]party.ID{{"a", "b", "c"}, {"c", "d", "e"}, {"a", "c", "e"}, {"b", "d", "e"}, {"a", "b", "c", "d", "e"}} {
		got, err := Open(ct, s.threshold, s.verification, s.answer(t, ct, set...))
		if err != nil {
			t.Fatalf("%v: %v", set, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%v opened %q, want %q", set, got, want)
		}
	}
}

// THE PROPERTY. t parties learn nothing. This is the whole reason the scheme
// exists, and it is the test to distrust first if the construction ever changes.
func TestTooFewPartiesLearnNothing(t *testing.T) {
	s := deal(t, 5, 2)
	ct, err := Encrypt(rand.Reader, s.public, []byte("one secret"))
	if err != nil {
		t.Fatal(err)
	}

	for _, set := range [][]party.ID{{"a"}, {"a", "b"}, {"d", "e"}} {
		_, err := Open(ct, s.threshold, s.verification, s.answer(t, ct, set...))
		if !errors.Is(err, ErrNotEnough) {
			t.Fatalf("%v: want ErrNotEnough, got %v", set, err)
		}
	}
}

// One party answering t+1 times is still one party. Counting answers rather
// than parties would make a 2-of-5 set openable by whoever holds one share.
func TestOnePartyCannotAnswerTwice(t *testing.T) {
	s := deal(t, 5, 2)
	ct, err := Encrypt(rand.Reader, s.public, []byte("one secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ct, s.threshold, s.verification, s.answer(t, ct, "a", "a", "a")); !errors.Is(err, ErrNotEnough) {
		t.Fatalf("want ErrNotEnough, got %v", err)
	}
}

// A wrong answer is named, not absorbed. Without the proof this would fail as
// "the ciphertext will not open" and say nothing about which party was at fault.
func TestAWrongAnswerIsNamed(t *testing.T) {
	s := deal(t, 5, 2)
	ct, err := Encrypt(rand.Reader, s.public, []byte("one secret"))
	if err != nil {
		t.Fatal(err)
	}
	answers := s.answer(t, ct, "a", "b", "c")

	// b answers with a point it cannot have derived from its share.
	answers[1].D = sample.Scalar(rand.Reader, s.group).Act(ct.R)

	_, err = Open(ct, s.threshold, s.verification, answers)
	if !errors.Is(err, ErrBadProof) {
		t.Fatalf("want ErrBadProof, got %v", err)
	}
	if err != nil && !bytes.Contains([]byte(err.Error()), []byte("b")) {
		t.Fatalf("the error does not name the party at fault: %v", err)
	}
}

// A party cannot answer under another party's name, which is what the proof's
// binding to the id is for: otherwise one share could fill every seat.
func TestAnAnswerCannotBeReplayedUnderAnotherName(t *testing.T) {
	s := deal(t, 5, 2)
	ct, err := Encrypt(rand.Reader, s.public, []byte("one secret"))
	if err != nil {
		t.Fatal(err)
	}
	a := s.answer(t, ct, "a")[0]

	stolen := &Answer{ID: "b", D: a.D, E: a.E, Z: a.Z}
	_, err = Open(ct, s.threshold, s.verification, append(s.answer(t, ct, "a", "c"), stolen))
	if !errors.Is(err, ErrBadProof) {
		t.Fatalf("want ErrBadProof, got %v", err)
	}
}

// Another group's shares do not open this ciphertext, even in the right number.
func TestAnotherGroupCannotOpenIt(t *testing.T) {
	mine := deal(t, 5, 2)
	theirs := deal(t, 5, 2)

	ct, err := Encrypt(rand.Reader, mine.public, []byte("one secret"))
	if err != nil {
		t.Fatal(err)
	}
	// Their answers are internally valid; they are answers to the wrong key.
	_, err = Open(ct, theirs.threshold, theirs.verification, theirs.answer(t, ct, "a", "b", "c"))
	if err == nil {
		t.Fatal("another group's shares opened the ciphertext")
	}
}

// A body moved onto another ephemeral point does not open, because R is the
// AEAD's additional data.
func TestABodyCannotBeMovedToAnotherCiphertext(t *testing.T) {
	s := deal(t, 5, 2)
	first, err := Encrypt(rand.Reader, s.public, []byte("first"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Encrypt(rand.Reader, s.public, []byte("second"))
	if err != nil {
		t.Fatal(err)
	}
	swapped := &Ciphertext{R: second.R, Body: first.Body}

	if _, err := Open(swapped, s.threshold, s.verification, s.answer(t, swapped, "a", "b", "c")); !errors.Is(err, ErrOpen) {
		t.Fatalf("want ErrOpen, got %v", err)
	}
}

// Two encryptions of one message share no bytes, so a store of these cannot be
// read by comparing records to each other.
func TestTwoEncryptionsOfOneMessageDiffer(t *testing.T) {
	s := deal(t, 5, 2)
	m := []byte("one secret")
	a, err := Encrypt(rand.Reader, s.public, m)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encrypt(rand.Reader, s.public, m)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.Body, b.Body) {
		t.Fatal("two encryptions of one message produced the same body")
	}
	if a.R.Equal(b.R) {
		t.Fatal("two encryptions reused an ephemeral point")
	}
}

// A 32-byte root is the thing this is for, so it is the size that is tested.
func TestARootKeyRoundTrips(t *testing.T) {
	s := deal(t, 3, 1)
	root := make([]byte, 32)
	if _, err := rand.Read(root); err != nil {
		t.Fatal(err)
	}
	ct, err := Encrypt(rand.Reader, s.public, root)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(ct, s.threshold, s.verification, s.answer(t, ct, "a", "b"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, root) {
		t.Fatal("the root did not survive the round trip")
	}
}

// A ciphertext and an answer survive a wire, and open on the other side. This
// is the property the whole distributed path rests on: the parties that answer
// are not the process that combines.
func TestTheWireCarriesBothHalves(t *testing.T) {
	s := deal(t, 5, 2)
	want := []byte("the root")

	ct, err := Encrypt(rand.Reader, s.public, want)
	if err != nil {
		t.Fatal(err)
	}
	ctBytes, err := ct.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	carried, err := UnmarshalCiphertext(s.group, ctBytes)
	if err != nil {
		t.Fatal(err)
	}

	var answers []*Answer
	for _, id := range []party.ID{"a", "b", "c"} {
		a, err := carried.Answer(rand.Reader, id, s.shares[id])
		if err != nil {
			t.Fatal(err)
		}
		b, err := a.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		back, err := UnmarshalAnswer(s.group, b)
		if err != nil {
			t.Fatal(err)
		}
		answers = append(answers, back)
	}

	got, err := Open(carried, s.threshold, s.verification, answers)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("opened %q, want %q", got, want)
	}
}

// An answer decoded under the wrong group is refused, not silently reinterpreted.
func TestTheWrongGroupDoesNotDecode(t *testing.T) {
	s := deal(t, 3, 1)
	ct, err := Encrypt(rand.Reader, s.public, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := ct.Answer(rand.Reader, "a", s.shares["a"])
	if err != nil {
		t.Fatal(err)
	}
	b, err := a.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalAnswer(curve.Ed25519{}, b); err == nil {
		t.Fatal("a secp256k1 answer decoded as ed25519")
	}
}

// An answer that names nobody cannot be built into a seat.
func TestAnAnswerMustNameAParty(t *testing.T) {
	s := deal(t, 3, 1)
	ct, _ := Encrypt(rand.Reader, s.public, []byte("x"))
	a, _ := ct.Answer(rand.Reader, "a", s.shares["a"])
	a.ID = ""
	b, err := a.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalAnswer(s.group, b); err == nil {
		t.Fatal("an answer naming no party decoded")
	}
}
