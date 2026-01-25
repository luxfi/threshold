package sign

import (
	"fmt"
	"io"

	"github.com/luxfi/threshold/pkg/hash"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/sample"
)

// messageHash is a wrapper around bytes to provide some domain separation.
type messageHash []byte

// WriteTo makes messageHash implement the io.WriterTo interface.
func (m messageHash) WriteTo(w io.Writer) (int64, error) {
	if m == nil {
		return 0, io.ErrUnexpectedEOF
	}
	n, err := w.Write(m)
	return int64(n), err
}

// Domain implements hash.WriterToWithDomain, and separates this type within hash.Hash.
func (messageHash) Domain() string {
	return "messageHash"
}

// Signature represents the result of a Schnorr signature.
//
// This signature claims to satisfy:
//
//	z * G = R + H(R, Y, m) * Y
//
// for a public key Y.
type Signature struct {
	// R is the commitment point.
	R curve.Point
	// z is the response scalar.
	z curve.Scalar
}

// NewSignature creates a new Signature from a commitment point R and response scalar z.
func NewSignature(R curve.Point, z curve.Scalar) *Signature {
	return &Signature{R: R, z: z}
}

// MarshalBinary serializes the signature to bytes in format: R (33 bytes) || z (32 bytes).
func (sig *Signature) MarshalBinary() ([]byte, error) {
	rBytes, err := sig.R.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal R: %w", err)
	}
	zBytes, err := sig.z.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal z: %w", err)
	}
	result := make([]byte, len(rBytes)+len(zBytes))
	copy(result[:len(rBytes)], rBytes)
	copy(result[len(rBytes):], zBytes)
	return result, nil
}

// UnmarshalBinary deserializes a signature from bytes.
// For x-only format (64 bytes): R_x (32 bytes) || z (32 bytes) - used by BIP-340 and precompiles.
// For compressed format (65 bytes): R (33 bytes) || z (32 bytes).
func (sig *Signature) UnmarshalBinary(group curve.Curve, data []byte) error {
	switch len(data) {
	case 64:
		// X-only format: R_x (32) || z (32)
		// Use LiftX for secp256k1 to recover the point from x-coordinate
		if secp, ok := group.(curve.Secp256k1); ok {
			R, err := secp.LiftX(data[:32])
			if err != nil {
				return fmt.Errorf("failed to lift x-coordinate for R: %w", err)
			}
			sig.R = R
		} else {
			return fmt.Errorf("x-only format only supported for secp256k1, got %s", group.Name())
		}
		sig.z = group.NewScalar()
		if err := sig.z.UnmarshalBinary(data[32:64]); err != nil {
			return fmt.Errorf("failed to unmarshal z: %w", err)
		}
	case 65:
		// Compressed format: R (33) || z (32)
		sig.R = group.NewPoint()
		if err := sig.R.UnmarshalBinary(data[:33]); err != nil {
			return fmt.Errorf("failed to unmarshal R: %w", err)
		}
		sig.z = group.NewScalar()
		if err := sig.z.UnmarshalBinary(data[33:65]); err != nil {
			return fmt.Errorf("failed to unmarshal z: %w", err)
		}
	default:
		return fmt.Errorf("invalid signature length: expected 64 or 65, got %d", len(data))
	}
	return nil
}

// Verify checks if a signature equation actually holds.
//
// Note that m is the hash of a message, and not the message itself.
func (sig Signature) Verify(public curve.Point, m []byte) bool {
	group := public.Curve()

	// Use canonical bytes for challenge computation - must match round2
	challengeHash := hash.New()
	rBytes, _ := sig.R.MarshalBinary()
	_ = challengeHash.WriteAny(&hash.BytesWithDomain{
		TheDomain: "R",
		Bytes:     rBytes,
	})
	yBytes, _ := public.MarshalBinary()
	_ = challengeHash.WriteAny(&hash.BytesWithDomain{
		TheDomain: "Y",
		Bytes:     yBytes,
	})
	_ = challengeHash.WriteAny(messageHash(m))
	challenge := sample.Scalar(challengeHash.Digest(), group)

	expected := challenge.Act(public)
	expected = expected.Add(sig.R)

	actual := sig.z.ActOnBase()

	return expected.Equal(actual)
}
