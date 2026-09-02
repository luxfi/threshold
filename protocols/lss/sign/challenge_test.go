package sign

import (
	"crypto/rand"
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/sample"
)

// A Schnorr challenge that does not cover the message is not a challenge.
//
// c = H(R ‖ Y ‖ m) is what both the signer and the verifier intend. Passing the
// concatenation to curve.FromHash does not hash it: FromHash truncates its
// input to the group order's byte length and reads it big-endian, which is the
// SECG convention for an ECDSA message digest and is not a hash function. Y and
// m fall off the end, the challenge is a function of R alone, and one signature
// then verifies under every message.
func TestASignatureCoversItsMessage(t *testing.T) {
	group := curve.Secp256k1{}
	x := sample.Scalar(rand.Reader, group)
	pub := x.ActOnBase()
	k := sample.Scalar(rand.Reader, group)
	R := k.ActOnBase()

	m := []byte("send alice one coin")
	c, err := challenge(group, R, pub, m)
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	// z = k + c·x, which is the sum the parties' shares interpolate to.
	sig := &SchnorrSignature{R: R, Z: group.NewScalar().Set(c).Mul(x).Add(k)}

	if !sig.Verify(pub, m) {
		t.Fatal("an honest signature did not verify")
	}
	if sig.Verify(pub, []byte("send bob one thousand coins")) {
		t.Fatal("the signature verified under a message it was never made over")
	}
}
