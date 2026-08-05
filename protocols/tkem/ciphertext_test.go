package tkem

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/party"
)

// TestClaim5_LabelBinding — two encapsulations under the same committee and the
// same randomness-free view must not produce interchangeable keys when their
// labels differ. Without this, a caller could open secret B with the material
// that opens secret A.
func TestClaim5_LabelBinding(t *testing.T) {
	g, shares := groupAndShares(t, runKeygen(t))

	ctA, keyA, err := Encapsulate(rand.Reader, g.PublicKey, []byte(testLabel))
	if err != nil {
		t.Fatalf("encapsulate A: %v", err)
	}
	ctB, keyB, err := Encapsulate(rand.Reader, g.PublicKey, []byte(altTestLabel))
	if err != nil {
		t.Fatalf("encapsulate B: %v", err)
	}
	if bytes.Equal(keyA, keyB) {
		t.Fatal("two labels produced the same key")
	}

	// The check above passes for the wrong reason on its own: the two
	// encapsulations used different randomness, so their keys would differ even
	// if the label never reached the derivation. Isolate the label by deriving
	// twice from IDENTICAL group elements. A caller that reused an ephemeral
	// scalar — a real bug, and one this binding survives — would otherwise get
	// one key for two different secrets.
	sameR, sameS := ctA.R, ctA.RBar
	derivedA, err := deriveKey(sameR, sameS, []byte(testLabel))
	if err != nil {
		t.Fatalf("derive A: %v", err)
	}
	derivedB, err := deriveKey(sameR, sameS, []byte(altTestLabel))
	if err != nil {
		t.Fatalf("derive B: %v", err)
	}
	if bytes.Equal(derivedA, derivedB) {
		t.Fatal("the same group elements under two labels produced one key — the label is not bound into the derivation")
	}

	// Relabelling a ciphertext must not silently produce a usable key. The
	// label is inside the well-formedness proof, so the edit is detected.
	tampered := &Ciphertext{R: ctA.R, RBar: ctA.RBar, E: ctA.E, F: ctA.F, Label: []byte(altTestLabel)}
	if err := tampered.Verify(); err == nil {
		t.Fatal("a relabelled ciphertext verified — the label is not bound into the proof")
	}
	if _, err := PartialDecapsulate(rand.Reader, shares[party.ID("a")], tampered); !errors.Is(err, ErrMalformedCiphertext) {
		t.Fatalf("a party accepted a relabelled ciphertext (err=%v)", err)
	}

	// And the honest B ciphertext must not open to A's key.
	gotB, err := Combine(g, ctB, partialsFrom(t, shares, ids()[:quorum], ctB))
	if err != nil {
		t.Fatalf("combine B: %v", err)
	}
	if bytes.Equal(gotB, keyA) {
		t.Fatal("ciphertext B decapsulated to key A")
	}
	if !bytes.Equal(gotB, keyB) {
		t.Fatal("ciphertext B did not decapsulate to its own key")
	}
}

// TestClaim5_CiphertextBinding — the derived key depends on R, not only on the
// Diffie-Hellman point. Two ciphertexts that somehow shared a shared-point must
// still yield different keys.
func TestClaim5_CiphertextBinding(t *testing.T) {
	g, shares := groupAndShares(t, runKeygen(t))
	ct, key, err := Encapsulate(rand.Reader, g.PublicKey, []byte(testLabel))
	if err != nil {
		t.Fatalf("encapsulate: %v", err)
	}

	// Recover the shared point the honest way, then derive with a DIFFERENT R.
	// If R were absent from the key derivation, this would reproduce the key.
	partials := partialsFrom(t, shares, ids()[:quorum], ct)
	otherCT, _, err := Encapsulate(rand.Reader, g.PublicKey, []byte(testLabel))
	if err != nil {
		t.Fatalf("encapsulate other: %v", err)
	}
	ids := make([]party.ID, len(partials))
	for i, p := range partials {
		ids[i] = p.ID
	}
	S := Curve().NewPoint()
	lambda := polynomial.Lagrange(Curve(), ids)
	for _, p := range partials {
		S = S.Add(lambda[p.ID].Act(p.D))
	}
	swapped, err := deriveKey(otherCT.R, S, ct.Label)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if bytes.Equal(swapped, key) {
		t.Fatal("swapping R left the key unchanged — R is not bound into the derivation")
	}
}

// TestClaim6_SealNeedsNoQuorum — encapsulation takes the public key and nothing
// else. This is the structural reason a compromised node cannot poison the
// store: it has no input to the sealing path at all.
//
// This is the property the preceding root-key-derivation design lacked. There,
// deriving the key required a live quorum, so a dishonest partial could steer
// what everything was sealed under. Here that failure mode does not exist.
func TestClaim6_SealNeedsNoQuorum(t *testing.T) {
	g, shares := groupAndShares(t, runKeygen(t))

	// Seal with only the public key in hand. No share, no party, no network.
	publicOnly := clonePoint(g.PublicKey)
	ct, key, err := Encapsulate(rand.Reader, publicOnly, []byte(testLabel))
	if err != nil {
		t.Fatalf("encapsulate: %v", err)
	}

	// A quorum assembled only afterwards opens it.
	got, err := Combine(g, ct, partialsFrom(t, shares, ids()[2:], ct))
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("a ciphertext sealed with only the public key did not open")
	}

	// Sealing under a key that is not the committee's must not open under it,
	// which is what makes "the public key is the only input" a real constraint
	// rather than a decorative one.
	stray, err := randScalar(rand.Reader)
	if err != nil {
		t.Fatalf("stray scalar: %v", err)
	}
	strayCT, _, err := Encapsulate(rand.Reader, stray.ActOnBase(), []byte(testLabel))
	if err != nil {
		t.Fatalf("encapsulate stray: %v", err)
	}
	strayKey, err := Combine(g, strayCT, partialsFrom(t, shares, ids()[:quorum], strayCT))
	if err != nil {
		t.Fatalf("combine stray: %v", err)
	}
	if bytes.Equal(strayKey, key) {
		t.Fatal("a ciphertext sealed to a foreign key opened to the committee's key")
	}
}

// TestClaim7_MalleatedCiphertextRefused — a party releases a partial only for a
// ciphertext whose author proved knowledge of the ephemeral scalar.
//
// Without that, the decapsulation endpoint is a Diffie-Hellman oracle: an
// adversary who captures a ciphertext submits a scalar multiple of it, gets the
// corresponding partials back, and divides out the scalar to recover the
// original key. The test performs exactly that attack and requires it to fail
// at the first step.
func TestClaim7_MalleatedCiphertextRefused(t *testing.T) {
	g, shares := groupAndShares(t, runKeygen(t))
	ct, key, err := Encapsulate(rand.Reader, g.PublicKey, []byte(testLabel))
	if err != nil {
		t.Fatalf("encapsulate: %v", err)
	}

	// The attacker knows a, and forms R' = a·R, RBar' = a·RBar. Both are
	// consistent with each other; what the attacker cannot do is produce a
	// proof, because it does not know log_G R'.
	a, err := randScalar(rand.Reader)
	if err != nil {
		t.Fatalf("attacker scalar: %v", err)
	}
	malleated := &Ciphertext{
		R:     cloneScalar(a).Act(ct.R),
		RBar:  cloneScalar(a).Act(ct.RBar),
		E:     ct.E,
		F:     ct.F,
		Label: ct.Label,
	}
	if err := malleated.Verify(); err == nil {
		t.Fatal("a malleated ciphertext verified — the proof does not bind R")
	}
	for _, id := range ids() {
		if _, err := PartialDecapsulate(rand.Reader, shares[id], malleated); !errors.Is(err, ErrMalformedCiphertext) {
			t.Fatalf("party %s served a malleated ciphertext (err=%v) — the endpoint is a Diffie-Hellman oracle", id, err)
		}
	}

	// The same attack with the proof fields also scaled fails too: the attacker
	// would need s' as well, and scaling f does not satisfy the verification.
	scaledProof := &Ciphertext{
		R:     cloneScalar(a).Act(ct.R),
		RBar:  cloneScalar(a).Act(ct.RBar),
		E:     ct.E,
		F:     cloneScalar(a).Mul(ct.F),
		Label: ct.Label,
	}
	if err := scaledProof.Verify(); err == nil {
		t.Fatal("scaling the response satisfied the proof — the sigma protocol is unsound as implemented")
	}

	// Sanity: the honest ciphertext still works, so the refusals above are not
	// simply everything failing.
	got, err := Combine(g, ct, partialsFrom(t, shares, ids()[:quorum], ct))
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("honest path broken: err=%v", err)
	}
}

// TestCombineRejectsDuplicateAndUnknownParties — a quorum is t DISTINCT
// parties. Counting one party's partial twice would let a single node meet the
// threshold on its own.
func TestCombineRejectsDuplicateAndUnknownParties(t *testing.T) {
	g, shares := groupAndShares(t, runKeygen(t))
	ct, _, err := Encapsulate(rand.Reader, g.PublicKey, []byte(testLabel))
	if err != nil {
		t.Fatalf("encapsulate: %v", err)
	}

	one := mustPartial(t, shares[party.ID("a")], ct)
	if _, err := Combine(g, ct, []*Partial{one, one, one}); !errors.Is(err, ErrDuplicateParty) {
		t.Fatalf("three copies of one partial met the threshold (err=%v)", err)
	}

	// A party that is not in the committee at all.
	outsider, err := randScalar(rand.Reader)
	if err != nil {
		t.Fatalf("outsider scalar: %v", err)
	}
	stranger, err := PartialDecapsulate(rand.Reader, Share{ID: "z", Secret: outsider}, ct)
	if err != nil {
		t.Fatalf("outsider partial: %v", err)
	}
	mixed := append(partialsFrom(t, shares, ids()[:quorum-1], ct), stranger)
	if _, err := Combine(g, ct, mixed); !errors.Is(err, ErrUnknownParty) {
		t.Fatalf("a partial from a non-member was accepted (err=%v)", err)
	}
}

// TestGeneratorHIsNotABaseMultipleAnyoneKnows checks the nothing-up-my-sleeve
// property of the second generator to the extent a test can: it is the image of
// a fixed tag under the one-way map, it is not the identity, and it is not the
// base point. If someone replaced it with s·G for a known s, the well-formedness
// proof would prove nothing.
func TestGeneratorHIsNotABaseMultipleAnyoneKnows(t *testing.T) {
	H := GeneratorH()
	if H.IsIdentity() {
		t.Fatal("H is the identity — the well-formedness proof is vacuous")
	}
	if H.Equal(Curve().NewBasePoint()) {
		t.Fatal("H is the base point")
	}
	// Determinism: the same tag must always give the same H, or two nodes would
	// disagree about what a valid ciphertext is.
	again := GeneratorH()
	if !H.Equal(again) {
		t.Fatal("H is not deterministic")
	}
	t.Logf("H = %x", enc(H))
}
