// SPDX-License-Identifier: BSD-3-Clause

package adapters

import (
	"crypto/rand"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/sample"
)

// GenerateEVMAddress must agree with what an EVM node computes when it
// ecrecovers a signature: Keccak256 over the 64-byte uncompressed public key,
// low 20 bytes.
//
// The regression this pins: curve.Point.MarshalBinary returns the 33-byte
// COMPRESSED encoding, so deriving from pubBytes[1:] hashes the 32-byte X
// coordinate alone. That yields a syntactically valid address for every key,
// belonging to no key at all — an unspendable destination that no unit test
// comparing "an address" to "an address" would catch. Only comparing against
// an independent derivation from the uncompressed key finds it.
func TestGenerateEVMAddressMatchesUncompressedKeccak(t *testing.T) {
	e := NewEVMAdapter(Ethereum)
	group := curve.Secp256k1{}

	for i := 0; i < 256; i++ {
		secret := sample.Scalar(rand.Reader, group)
		point := secret.ActOnBase()

		got, ok := e.GenerateEVMAddress(point)
		if !ok {
			t.Fatalf("iteration %d: GenerateEVMAddress reported failure on a valid point", i)
		}

		// Independent reference derivation straight from the secret scalar,
		// via decred's secp256k1 rather than the adapter's own code path.
		compressed, err := point.MarshalBinary()
		if err != nil {
			t.Fatalf("iteration %d: marshal: %v", i, err)
		}
		pub, err := secp256k1.ParsePubKey(compressed)
		if err != nil {
			t.Fatalf("iteration %d: parse: %v", i, err)
		}
		uncompressed := pub.SerializeUncompressed()
		if len(uncompressed) != 65 || uncompressed[0] != 0x04 {
			t.Fatalf("iteration %d: bad uncompressed encoding", i)
		}
		h := sha3.NewLegacyKeccak256()
		h.Write(uncompressed[1:])
		var want [20]byte
		copy(want[:], h.Sum(nil)[12:])

		if got != want {
			t.Fatalf("iteration %d: address = 0x%x, want 0x%x", i, got, want)
		}

		// The specific wrong answer the old code produced, spelled out, so
		// that reintroducing it fails loudly rather than silently.
		hWrong := sha3.NewLegacyKeccak256()
		hWrong.Write(compressed[1:]) // 32-byte X only
		var compressedDerived [20]byte
		copy(compressedDerived[:], hWrong.Sum(nil)[12:])
		if got == compressedDerived {
			t.Fatalf("iteration %d: address was derived from the COMPRESSED point; "+
				"EVM requires Keccak over uncompressed X‖Y", i)
		}
	}
}

// Both Y-parities must derive correctly. An implementation that drops parity
// (or assumes even-Y) is right for about half of all keys, which is exactly
// the sort of bug that survives a small test sample.
func TestGenerateEVMAddressHandlesBothYParities(t *testing.T) {
	e := NewEVMAdapter(Ethereum)
	group := curve.Secp256k1{}

	seenEven, seenOdd := false, false
	for i := 0; i < 512 && !(seenEven && seenOdd); i++ {
		point := sample.Scalar(rand.Reader, group).ActOnBase()
		compressed, err := point.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}

		addr, ok := e.GenerateEVMAddress(point)
		if !ok {
			t.Fatalf("GenerateEVMAddress failed on a valid point")
		}
		if addr == ([20]byte{}) {
			t.Fatalf("derived the zero address for parity byte 0x%02x", compressed[0])
		}

		switch compressed[0] {
		case 0x02:
			seenEven = true
		case 0x03:
			seenOdd = true
		default:
			t.Fatalf("unexpected compressed prefix 0x%02x", compressed[0])
		}
	}
	if !seenEven || !seenOdd {
		t.Fatalf("did not exercise both Y parities (even=%v odd=%v)", seenEven, seenOdd)
	}
}

// The identity point has no address. Returning ok=false is the contract;
// returning a plausible-looking [20]byte would be the dangerous behaviour.
func TestGenerateEVMAddressRejectsIdentity(t *testing.T) {
	e := NewEVMAdapter(Ethereum)
	if _, ok := e.GenerateEVMAddress(curve.Secp256k1{}.NewPoint()); ok {
		t.Fatal("GenerateEVMAddress accepted the identity point; it has no EVM address")
	}
}
