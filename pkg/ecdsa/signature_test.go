package ecdsa

import (
	"bytes"
	"crypto/rand"
	"testing"

	decredecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/sample"
)

func NewSignature(x curve.Scalar, hash []byte, k curve.Scalar) *Signature {
	group := x.Curve()

	if k == nil {
		k = sample.Scalar(rand.Reader, group)
	}
	m := curve.FromHash(group, hash)
	kInv := group.NewScalar().Set(k).Invert()
	R := kInv.ActOnBase()
	r := R.XScalar()
	s := r.Mul(x).Add(m).Mul(k)
	return &Signature{
		R: R,
		S: s,
	}
}

// recoverCompressed recovers the compressed secp256k1 public key from a
// 65-byte Ethereum-format signature (R‖S‖V, V in {0,1}) over hash, via the
// decred secp256k1 library — the same recovery routine luxfi/mpc uses and the
// cryptographic operation luxfi/evm's ecrecover performs on a tx signature.
// A wrong recovery id or a non-canonical S makes this resolve to the wrong
// key (or fail) — exactly how the EVM would reject the emitted signature.
func recoverCompressed(t *testing.T, hash, eth []byte) []byte {
	t.Helper()
	if len(eth) != 65 {
		t.Fatalf("sig len = %d, want 65", len(eth))
	}
	compact := make([]byte, 65)
	compact[0] = 27 + eth[64] // decred compact header for an uncompressed key
	copy(compact[1:], eth[:64])
	pub, _, err := decredecdsa.RecoverCompact(compact, hash)
	if err != nil {
		t.Fatalf("RecoverCompact: %v", err)
	}
	return pub.SerializeCompressed()
}

// SigEthereum must emit a signature luxfi/evm accepts: EIP-2 low-S, a correct
// recovery id, and a signer public key that ecrecover resolves back to. This
// is the property the KMS /sign path was violating (raw high-S, no v). 256
// random signatures exercise both the low-S and high-S branches (~half of
// random ECDSA S values are high-S).
func TestSigEthereum_EVMRecoverable(t *testing.T) {
	group := curve.Secp256k1{}
	for i := 0; i < 256; i++ {
		x := sample.Scalar(rand.Reader, group)
		wantPub, err := x.ActOnBase().MarshalBinary() // signer's compressed pubkey
		if err != nil {
			t.Fatalf("pub marshal: %v", err)
		}
		hash := make([]byte, 32)
		if _, err := rand.Read(hash); err != nil {
			t.Fatalf("rand: %v", err)
		}
		sig := NewSignature(x, hash, nil)

		rBefore, _ := sig.R.MarshalBinary()
		sBefore, _ := sig.S.MarshalBinary()

		eth, err := sig.SigEthereum()
		if err != nil {
			t.Fatalf("SigEthereum: %v", err)
		}
		if len(eth) != 65 {
			t.Fatalf("len = %d, want 65", len(eth))
		}
		if eth[64] > 1 {
			t.Fatalf("v = %d, want recovery id in {0,1}", eth[64])
		}

		// EIP-2 low-S: the emitted S must not be over half order.
		sScalar := group.NewScalar()
		if err := sScalar.UnmarshalBinary(eth[32:64]); err != nil {
			t.Fatalf("emitted S unmarshal: %v", err)
		}
		if sScalar.IsOverHalfOrder() {
			t.Fatal("emitted S is high-S; EIP-2 normalization failed")
		}

		// The ecrecover proof: recovery resolves the signer's public key.
		if got := recoverCompressed(t, hash, eth); !bytes.Equal(got, wantPub) {
			t.Fatalf("ecrecover pubkey mismatch:\n got  %x\n want %x", got, wantPub)
		}

		// Non-mutation: the receiver's R and S are untouched.
		rAfter, _ := sig.R.MarshalBinary()
		sAfter, _ := sig.S.MarshalBinary()
		if !bytes.Equal(rBefore, rAfter) || !bytes.Equal(sBefore, sAfter) {
			t.Fatal("SigEthereum mutated its receiver signature")
		}
	}
}

// A signature whose raw S is above half order must be flipped to low-S with a
// correspondingly flipped recovery id, and STILL recover to the signer. This
// pins the exact high-S branch a random draw only hits probabilistically.
func TestSigEthereum_NormalizesHighS(t *testing.T) {
	group := curve.Secp256k1{}
	for i := 0; i < 4096; i++ {
		x := sample.Scalar(rand.Reader, group)
		wantPub, _ := x.ActOnBase().MarshalBinary()
		hash := make([]byte, 32)
		rand.Read(hash)
		sig := NewSignature(x, hash, nil)

		// Only keep draws whose raw S is high-S — the branch under test.
		if !sig.S.IsOverHalfOrder() {
			continue
		}
		eth, err := sig.SigEthereum()
		if err != nil {
			t.Fatalf("SigEthereum: %v", err)
		}
		sScalar := group.NewScalar()
		if err := sScalar.UnmarshalBinary(eth[32:64]); err != nil {
			t.Fatalf("S unmarshal: %v", err)
		}
		if sScalar.IsOverHalfOrder() {
			t.Fatal("high-S input was not normalized to low-S")
		}
		if got := recoverCompressed(t, hash, eth); !bytes.Equal(got, wantPub) {
			t.Fatalf("high-S normalized pubkey mismatch:\n got  %x\n want %x", got, wantPub)
		}
		return // proved the high-S branch once end to end
	}
	t.Skip("no high-S signature drawn in 4096 attempts (astronomically unlikely)")
}

func TestSignature_Verify(t *testing.T) {
	group := curve.Secp256k1{}

	m := []byte("hello")
	x := sample.Scalar(rand.Reader, group)
	X := x.ActOnBase()
	sig := NewSignature(x, m, nil)
	if !sig.Verify(X, m) {
		t.Error("verify failed")
	}
}

func TestSignature_Verify_Zero(t *testing.T) {
	group := curve.Secp256k1{}

	m := []byte("any message is valid")
	x := sample.Scalar(rand.Reader, group)
	X := x.ActOnBase()

	// s = 0
	s := group.NewScalar()
	if !s.IsZero() {
		t.Error("s should be zero")
		return
	}
	R := s.ActOnBase()
	sig := &Signature{
		R: R,
		S: s,
	}
	if sig.Verify(X, m) {
		t.Error("zero R/S signature should not verify")
	}
}
