package jvss

import (
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/party"
)

// A verifiable sharing has to accept an honest share. The commitment is the
// dealer's polynomial in the exponent, so the check is F(x) == [f(x)]·G.
func TestAnHonestShareVerifies(t *testing.T) {
	ids := []party.ID{"a", "b", "c"}
	j := NewJVSS(curve.Secp256k1{}, 2, ids, "a")
	shares, commitment, _, err := j.GenerateShares()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	for _, id := range ids {
		if !j.VerifyShare(shares[id], commitment, id) {
			t.Errorf("party %s: an honest share was rejected", id)
		}
	}
}

// The negative controls, without which the test above passes against a
// VerifyShare that answers true unconditionally.
func TestVerifyShareRejectsWhatItShould(t *testing.T) {
	group := curve.Secp256k1{}
	ids := []party.ID{"a", "b", "c"}
	j := NewJVSS(group, 2, ids, "a")
	shares, commitment, _, err := j.GenerateShares()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if j.VerifyShare(shares["a"], commitment, "b") {
		t.Error("a's share verified as b's")
	}
	// Another dealer's commitment describes another polynomial.
	_, other, _, err := j.GenerateShares()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if j.VerifyShare(shares["a"], other, "a") {
		t.Error("a share verified against a commitment it does not belong to")
	}
	if j.VerifyShare(&Share{Value: group.NewScalar()}, commitment, "a") {
		t.Error("a zero share verified")
	}
	if j.VerifyShare(nil, commitment, "a") || j.VerifyShare(shares["a"], nil, "a") {
		t.Error("a nil argument verified")
	}
}

// The whole protocol has to complete. VerifyAndCombine gates every share on
// VerifyShare, so a sharing that cannot verify cannot reshare at all — the
// failure this package was in reached exactly here, as "invalid share from a
// to a" for a set of shares that were all honest.
func TestVerifyAndCombineCompletes(t *testing.T) {
	ids := []party.ID{"a", "b", "c"}
	j := NewJVSS(curve.Secp256k1{}, 2, ids, "a")

	byDealer := make(map[party.ID]map[party.ID]*Share, len(ids))
	commitments := make(map[party.ID]*polynomial.Exponent, len(ids))
	for _, dealer := range ids {
		shares, commitment, _, err := j.GenerateShares()
		if err != nil {
			t.Fatalf("dealer %s: %v", dealer, err)
		}
		byDealer[dealer] = shares
		commitments[dealer] = commitment
	}

	if _, err := j.VerifyAndCombine(byDealer, commitments); err != nil {
		t.Fatalf("an honest round did not complete: %v", err)
	}

	// And a corrupted share is still refused, by name.
	byDealer["b"]["c"] = &Share{Value: curve.Secp256k1{}.NewScalar()}
	if _, err := j.VerifyAndCombine(byDealer, commitments); err == nil {
		t.Fatal("a corrupted share was combined")
	}
}
