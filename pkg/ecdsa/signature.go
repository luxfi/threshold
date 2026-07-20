package ecdsa

import (
	"fmt"

	"github.com/luxfi/threshold/pkg/math/curve"
)

type Signature struct {
	R curve.Point
	S curve.Scalar
}

// EmptySignature returns a new signature with a given curve, ready to be unmarshalled.
func EmptySignature(group curve.Curve) Signature {
	return Signature{R: group.NewPoint(), S: group.NewScalar()}
}

// Verify is a custom signature format using curve data.
func (sig Signature) Verify(X curve.Point, hash []byte) bool {
	group := X.Curve()

	r := sig.R.XScalar()
	if r.IsZero() || sig.S.IsZero() {
		return false
	}

	m := curve.FromHash(group, hash)
	sInv := group.NewScalar().Set(sig.S).Invert()
	mG := m.ActOnBase()
	rX := r.Act(X)
	R2 := mG.Add(rX)
	R2 = sInv.Act(R2)
	return R2.Equal(sig.R)
}

// SigEthereum returns the signature as a 65-byte Ethereum-format compact
// signature: R.x (32) ‖ S (32) ‖ V (1).
//
// It enforces EIP-2 low-S: an S above secp256k1n/2 is negated and the
// recovery parity flipped, so the output is always canonical and accepted by
// luxfi/geth (go-ethereum) ecrecover. A high-S signature is otherwise
// rejected as "invalid sender". V is the recovery id (0 or 1), derived from
// the compressed-R Y-parity byte.
//
// The receiver signature is left unmodified — curve.Scalar/Point are
// pointer-backed, so S is copied before normalization to avoid aliasing the
// caller's value.
func (sig Signature) SigEthereum() ([]byte, error) {
	group := sig.R.Curve()
	s := group.NewScalar().Set(sig.S)
	overHalf := s.IsOverHalfOrder() // s-values greater than secp256k1n/2 are non-canonical
	if overHalf {
		s.Negate()
	}

	rBytes, err := sig.R.MarshalBinary() // compressed point: 0x02|0x03 ‖ X(32)
	if err != nil {
		return nil, err
	}
	if len(rBytes) != 33 {
		return nil, fmt.Errorf("ecdsa: unexpected compressed R length %d, want 33", len(rBytes))
	}
	sBytes, err := s.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if len(sBytes) != 32 {
		return nil, fmt.Errorf("ecdsa: unexpected S length %d, want 32", len(sBytes))
	}

	out := make([]byte, 65)
	copy(out[0:32], rBytes[1:]) // X coordinate (drop the parity prefix)
	copy(out[32:64], sBytes)    // low-S
	v := rBytes[0] - 2          // 0x02 -> 0, 0x03 -> 1: Y parity is the recovery id
	if overHalf {
		v ^= 1 // negating S flips the recovery parity
	}
	out[64] = v
	return out, nil
}
