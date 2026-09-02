package sign

import (
	"github.com/luxfi/threshold/pkg/hash"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/sample"
)

// challenge is the Schnorr challenge c = H(R ‖ Y ‖ m). It lives in one place so
// the signer and the verifier cannot drift apart, and it hashes, which is what
// makes it cover the message: each piece goes in length- and domain-separated,
// and the digest is read wide.
func challenge(group curve.Curve, R, public curve.Point, message []byte) (curve.Scalar, error) {
	h := hash.New()
	if err := h.WriteAny(R, public, message); err != nil {
		return nil, err
	}
	return sample.Scalar(h.Digest(), group), nil
}
