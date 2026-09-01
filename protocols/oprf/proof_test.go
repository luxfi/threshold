package oprf

import (
	"bytes"
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/party"
)

// RFC 9497 A.1.2.1 — the first VOPRF vector for ristretto255-SHA512.
//
// This decides whether the proof is the one the RFC defines rather than a
// self-consistent one of my own. It pins the transcript byte-for-byte: the
// element ORDER, the length prefixes, the two domain tags, and the mode byte
// that separates this from the plain evaluation. A proof that verifies against
// itself and disagrees here interoperates with nothing.
const (
	vSkSm      = "e6f73f344b79b379f1a0dd37e07ff62e38d9f71345ce62ae3a9bc60b04ccd909"
	vPkSm      = "c803e2cc6b05fc15064549b5920659ca4a77b2cca6f04f6b357009335476ad4e"
	vInput     = "00"
	vBlind     = "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"
	vBlinded   = "863f330cc1a1259ed5a5998a23acfd37fb4351a793a5b3c090b642ddc439b945"
	vEvaluated = "aa8fa048764d5623868679402ff6108d2521884fa138cd7f9c7669a9a014267e"
	vProof     = "ddef93772692e535d1a53903db24367355cc2cc78de93b3be5a8ffcc6985dd066d4346421d17bf5117a2a1ff0fcb2a759f58a539dfbe857a40bce4cf49ec600d"
	vProofRand = "222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e"
)

// scalarReader drives sample() to a chosen scalar, so a randomised proof can be
// compared byte for byte with the RFC's rather than merely accepted.
//
// It has to encode the scalar the way sample() will read it, which is not the
// way the RFC writes it down. sample() reads 64 bytes and calls curve.FromHash,
// and FromHash keeps only the FIRST 32, reads them BIG-endian, and right-shifts
// by three because the order is 253 bits. The bytes that yield r are therefore
// the big-endian encoding of r·8 — not r little-endian, and not a wide reduction
// over all 64.
type scalarReader struct{ b []byte }

func (f *scalarReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	copy(p, f.b)
	return len(p), nil
}

// readerFor returns a reader that makes sample() produce the scalar written in
// RFC order (little-endian) as hexStr.
func readerFor(t *testing.T, hexStr string) *scalarReader {
	t.Helper()
	le := mustHex(t, hexStr)
	be := make([]byte, len(le))
	for i := range le {
		be[i] = le[len(le)-1-i]
	}
	r := new(big.Int).SetBytes(be)
	r.Lsh(r, 3) // undo FromHash's right-shift by three
	buf := make([]byte, 32)
	r.FillBytes(buf)
	return &scalarReader{b: buf}
}

// The reader is worth its own check: if it did not reproduce the vector's
// scalar the proof comparison below would be testing two wrong things against
// each other.
func TestTheVectorsProofScalarIsWhatSampleReturns(t *testing.T) {
	got := sample(readerFor(t, vProofRand))
	if want := scalarFrom(t, vProofRand); !got.Equal(want) {
		gb, _ := got.MarshalBinary()
		t.Fatalf("sample did not reproduce the vector's proof scalar: got %x", gb)
	}
}

// THE PROVER, not just the verifier. The vector test below feeds the RFC's own
// proof to Verify, which pins one direction: a Prove that emitted anything at
// all would go unnoticed. Pinning the randomness makes the other direction
// comparable, and the bytes must match the RFC's exactly.
func TestRFC9497VOPRFVectorProver(t *testing.T) {
	k := scalarFrom(t, vSkSm)
	p, err := Prove(readerFor(t, vProofRand), k, pointFrom(t, vPkSm),
		pointFrom(t, vBlinded), pointFrom(t, vEvaluated))
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	want := proofFrom(t, vProof)
	if !p.C.Equal(want.C) || !p.S.Equal(want.S) {
		cb, _ := p.C.MarshalBinary()
		sb, _ := p.S.MarshalBinary()
		t.Fatalf("proof does not match RFC 9497 A.1.2.1\n got c=%x s=%x\nwant %s", cb, sb, vProof)
	}
}

func TestRFC9497VOPRFVector(t *testing.T) {
	blinded := pointFrom(t, vBlinded)
	evaluated := pointFrom(t, vEvaluated)
	k := scalarFrom(t, vSkSm)
	pub := pointFrom(t, vPkSm)

	// The public key is the key on the generator — checked, because everything
	// below is a statement relating the two and a mismatch would make the whole
	// test vacuous.
	if got := k.ActOnBase(); !got.Equal(pub) {
		gb, _ := got.MarshalBinary()
		t.Fatalf("skSm·G != pkSm\n got %x\nwant %s", gb, vPkSm)
	}

	// The evaluation itself.
	if got := EvaluateWhole(k, blinded); !got.Equal(evaluated) {
		gb, _ := got.MarshalBinary()
		t.Fatalf("evaluated element\n got %x\nwant %s", gb, vEvaluated)
	}

	// And the proof over it must verify.
	p := proofFrom(t, vProof)
	if err := Verify(pub, blinded, evaluated, p); err != nil {
		t.Fatalf("the RFC's own proof did not verify: %v", err)
	}
}

// A proof over a DIFFERENT answer must not verify. Without this the test above
// would pass against a Verify that returned nil unconditionally.
func TestAProofDoesNotCoverAnotherAnswer(t *testing.T) {
	blinded := pointFrom(t, vBlinded)
	pub := pointFrom(t, vPkSm)
	p := proofFrom(t, vProof)

	// Someone else's key applied to the same blinded element: a well-formed
	// group element, and not the one the proof is about.
	other := sample(rand.Reader).Act(blinded)
	if err := Verify(pub, blinded, other, p); err == nil {
		t.Fatal("a proof verified against an answer it was not made for")
	}
}

// Round trip with our own prover, which is what a party actually runs.
func TestProveAndVerifyRoundTrip(t *testing.T) {
	k := sample(rand.Reader)
	pub := k.ActOnBase()

	_, blinded, err := Request(rand.Reader, []byte("correct horse battery staple"))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	answer := EvaluateWhole(k, blinded)

	p, err := Prove(rand.Reader, k, pub, blinded, answer)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if err := Verify(pub, blinded, answer, p); err != nil {
		t.Fatalf("our own proof did not verify: %v", err)
	}

	// A proof made for one party must not verify against another's key — that
	// is what stops a committee member replaying a neighbour's answer as its own.
	otherPub := sample(rand.Reader).ActOnBase()
	if err := Verify(otherPub, blinded, answer, p); err == nil {
		t.Fatal("a proof verified against a different party's public key")
	}
}

func proofFrom(t *testing.T, hexStr string) *Proof {
	t.Helper()
	raw := mustHex(t, hexStr)
	if len(raw) != 64 {
		t.Fatalf("proof is %d bytes, want 64", len(raw))
	}
	return &Proof{C: scalarFromBytes(t, raw[:32]), S: scalarFromBytes(t, raw[32:])}
}

func scalarFromBytes(t *testing.T, le []byte) curve.Scalar {
	t.Helper()
	be := make([]byte, len(le))
	for i := range le {
		be[i] = le[len(le)-1-i]
	}
	s := group.NewScalar()
	if err := s.UnmarshalBinary(be); err != nil {
		t.Fatalf("scalar %x: %v", le, err)
	}
	return s
}

// shareVerifiable splits k and gives each party its commitment alongside it.
func shareVerifiable(t *testing.T, k curve.Scalar, domain []party.ID, degree int) (map[party.ID]Key, map[party.ID]curve.Point) {
	t.Helper()
	poly := polynomial.NewPolynomial(group, degree, k)
	keys := make(map[party.ID]Key, len(domain))
	pubs := make(map[party.ID]curve.Point, len(domain))
	for _, id := range domain {
		sh := poly.Evaluate(id.Scalar(group))
		keys[id] = Key{Party: id, Share: sh, Public: sh.ActOnBase()}
		pubs[id] = keys[id].Public
	}
	return keys, pubs
}

// THE POINT OF THE VERIFIABLE MODE: a party that returns a wrong element is
// refused BY NAME, where the plain path folds it in and yields a key that is
// merely wrong — which, to the person typing, looks exactly like a wrong
// password. Those are different facts and a committee has to be able to say
// which one happened.
func TestALyingPartyIsNamedRatherThanFoldedIn(t *testing.T) {
	domain := []party.ID{"a", "b", "c", "d", "e"}
	const degree = 2 // t = 3

	k := sample(rand.Reader)
	keys, pubs := shareVerifiable(t, k, domain, degree)

	blind, blinded, err := Request(rand.Reader, []byte("hunter2"))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	want, err := blind.Finalize(EvaluateWhole(k, blinded))
	if err != nil {
		t.Fatalf("finalize whole: %v", err)
	}

	honest := func(ids ...party.ID) map[party.ID]Answer {
		out := make(map[party.ID]Answer, len(ids))
		for _, id := range ids {
			a, err := EvaluateVerifiable(rand.Reader, keys[id], blinded)
			if err != nil {
				t.Fatalf("evaluate %s: %v", id, err)
			}
			out[id] = a
		}
		return out
	}

	// An honest quorum verifies and reproduces the undivided key's answer.
	answers := honest("a", "b", "c")
	combined, err := CombineVerified(domain, pubs, k.ActOnBase(), blinded, answers)
	if err != nil {
		t.Fatalf("honest quorum refused: %v", err)
	}
	got, err := blind.Finalize(combined)
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("an honest verified quorum disagreed with the undivided key")
	}

	// Now c lies: a well-formed element, just not its own share applied.
	lying := honest("a", "b", "c")
	lying["c"] = Answer{Element: sample(rand.Reader).Act(blinded), Proof: lying["c"].Proof}

	_, err = CombineVerified(domain, pubs, k.ActOnBase(), blinded, lying)
	if err == nil {
		t.Fatal("a wrong element was folded in; the client would have derived a wrong key and blamed the password")
	}
	if !strings.Contains(err.Error(), "\"c\"") {
		t.Errorf("the refusal does not name the party that lied: %v", err)
	}

	// And the plain path, for contrast, accepts it silently and yields a key
	// that is simply wrong — which is the failure this mode exists to end.
	plain := map[party.ID]curve.Point{}
	for id, a := range lying {
		plain[id] = a.Element
	}
	bad, err := Combine(domain, plain)
	if err != nil {
		t.Fatalf("plain combine: %v", err)
	}
	badKey, err := blind.Finalize(bad)
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if bytes.Equal(badKey, want) {
		t.Fatal("the lie produced the right key, so this test proves nothing")
	}
}

// A PROOF SAYS "THIS ANSWER IS MADE WITH THAT SHARE". It does not say the share
// belongs to the key the client came to evaluate under, and until the shares
// are tied back to K nothing does: a client handed a substituted committee
// checks every proof against the substituted shares, finds them all valid, and
// derives its output under a key someone else chose. With a password behind the
// input that is the whole game — the attacker learns F(k',pw) for a k' it knows.
func TestASubstitutedCommitteeIsRefusedAlthoughEveryProofIsValid(t *testing.T) {
	domain := []party.ID{"a", "b", "c", "d", "e"}
	k := sample(rand.Reader)
	const degree = 2 // t = 3, matching the three parties that answer below
	keys, pubs := shareVerifiable(t, k, domain, degree)

	// A second, entirely honest committee over a DIFFERENT key. Every party in
	// it answers correctly and proves it correctly.
	other := sample(rand.Reader)
	otherKeys, otherPubs := shareVerifiable(t, other, domain, degree)

	blind, blinded, err := RequestVerifiable(rand.Reader, []byte("hunter2"))
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	answers := make(map[party.ID]Answer, 3)
	for _, id := range []party.ID{"a", "b", "c"} {
		a, err := EvaluateVerifiable(rand.Reader, otherKeys[id], blinded)
		if err != nil {
			t.Fatalf("evaluate %s: %v", id, err)
		}
		answers[id] = a
		// Each proof is valid against the substituted share it was made with.
		if err := Verify(otherPubs[id], blinded, a.Element, a.Proof); err != nil {
			t.Fatalf("the substituted committee's own proof does not verify: %v", err)
		}
	}

	// Asked for K, given k'. Every proof checks out and the answer is still wrong.
	if _, err := CombineVerified(domain, otherPubs, k.ActOnBase(), blinded, answers); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("a substituted committee was accepted for another key: %v", err)
	}

	// The same committee asked for its own key is fine — the check refuses a
	// substitution, not a committee.
	combined, err := CombineVerified(domain, otherPubs, other.ActOnBase(), blinded, answers)
	if err != nil {
		t.Fatalf("the committee was refused for its own key: %v", err)
	}
	got, err := blind.Finalize(combined)
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	want, err := blind.Finalize(EvaluateWhole(other, blinded))
	if err != nil {
		t.Fatalf("finalize whole: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("the accepted quorum disagreed with its own undivided key")
	}
	_ = keys
	_ = pubs
}

// An identity element does not satisfy the DLEQ relation, it collapses it. With
// blinded = answer = identity, M and Z are the identity, so t3 = s·M + c·Z is
// the identity whatever (c,s) are, and the relation degenerates to a Schnorr
// proof of knowledge of dlog(pub) — which says nothing at all about the answer.
func TestVerifyRefusesAnIdentityElement(t *testing.T) {
	k := sample(rand.Reader)
	pub := k.ActOnBase()
	id := group.NewPoint() // the identity

	// A proof made over the identity pair, by the honest prover.
	p, err := Prove(rand.Reader, k, pub, id, id)
	if err == nil {
		if err := Verify(pub, id, id, p); err == nil {
			t.Fatal("a proof over the identity pair verified; it proves nothing about the answer")
		}
	}

	// And a real proof is not accepted once either element is replaced by the
	// identity.
	_, blinded, err := RequestVerifiable(rand.Reader, []byte("x"))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	answer := k.Act(blinded)
	good, err := Prove(rand.Reader, k, pub, blinded, answer)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if err := Verify(pub, blinded, answer, good); err != nil {
		t.Fatalf("the honest proof was refused: %v", err)
	}
	if err := Verify(pub, id, answer, good); err == nil {
		t.Error("an identity blinded element was accepted")
	}
	if err := Verify(pub, blinded, id, good); err == nil {
		t.Error("an identity answer was accepted")
	}
}

// The share and its commitment travel together in a Key so they can be checked
// against each other. A mismatch makes every proof this party emits
// unverifiable, which reads as "the committee is lying" rather than as the key
// having been assembled wrong.
func TestAKeyWhosePublicIsNotItsOwnCommitmentIsRefused(t *testing.T) {
	k := Key{Party: "a", Share: sample(rand.Reader), Public: sample(rand.Reader).ActOnBase()}
	_, blinded, err := RequestVerifiable(rand.Reader, []byte("x"))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if _, err := EvaluateVerifiable(rand.Reader, k, blinded); err == nil {
		t.Fatal("a key whose public share is another share's commitment was used to prove")
	}
	// The same share with its own commitment is fine.
	k.Public = k.Share.ActOnBase()
	if _, err := EvaluateVerifiable(rand.Reader, k, blinded); err != nil {
		t.Fatalf("a well-formed key was refused: %v", err)
	}
}
