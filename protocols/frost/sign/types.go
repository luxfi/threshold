package sign

import (
	"crypto/ed25519"
	"crypto/sha512"
	"fmt"
	"io"

	"github.com/gtank/merlin"
	r255 "github.com/gtank/ristretto255"
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

// ed25519Challenge computes the RFC 8032 §5.1.6 challenge
//
//	k = SHA-512(R ‖ A ‖ M) mod L
//
// R and A are the 32-byte compressed Edwards encodings of the commitment and the
// public key, and M is the raw message: this is PureEdDSA, so M is NOT pre-hashed
// and no domain prefix is applied. The digest is reduced with the wide
// little-endian reduction, making k byte-identical to the k crypto/ed25519
// derives when it verifies.
//
// This is the only place the challenge is computed. Round 2 calls it to sign;
// the RFC 8032 vector tests call it to check it against the standard.
func ed25519Challenge(group curve.Curve, RBytes, ABytes, message []byte) (curve.Scalar, error) {
	s, ok := group.NewScalar().(*curve.Ed25519Scalar)
	if !ok {
		return nil, fmt.Errorf("ed25519 signing requires the ed25519 group, got %q", group.Name())
	}
	h := sha512.New()
	h.Write(RBytes)
	h.Write(ABytes)
	h.Write(message)
	if _, err := s.SetUniformBytes(h.Sum(nil)); err != nil {
		return nil, fmt.Errorf("failed to derive ed25519 challenge: %w", err)
	}
	return s, nil
}

// Ed25519Signature is an RFC 8032 PureEdDSA signature over edwards25519.
//
// The wire encoding is the 64 bytes R ‖ S: R is the compressed Edwards encoding
// of the commitment point, and S is the response scalar in LITTLE-endian order.
// curve.Scalar.MarshalBinary is big-endian by interface contract, so the byte
// order is reversed here — and only here, at the RFC 8032 boundary.
type Ed25519Signature struct {
	// R is the commitment point.
	R curve.Point
	// S is the response scalar.
	S curve.Scalar
}

// MarshalBinary serializes the signature as the 64 bytes R ‖ S required by
// RFC 8032 §5.1.6, with S little-endian.
func (sig Ed25519Signature) MarshalBinary() ([]byte, error) {
	if sig.R == nil || sig.S == nil {
		return nil, fmt.Errorf("ed25519 signature has nil fields")
	}
	RBytes, err := sig.R.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal R: %w", err)
	}
	sBE, err := sig.S.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal S: %w", err)
	}
	if len(RBytes) != 32 || len(sBE) != 32 {
		return nil, fmt.Errorf("ed25519 signature parts must be 32 bytes, got R=%d S=%d", len(RBytes), len(sBE))
	}
	out := make([]byte, ed25519.SignatureSize)
	copy(out[:32], RBytes)
	for i := 0; i < 32; i++ {
		out[32+i] = sBE[31-i]
	}
	return out, nil
}

// UnmarshalBinary deserializes a 64-byte RFC 8032 signature. group must be
// curve.Ed25519. Decoding R enforces prime-order subgroup membership, and
// decoding S rejects any non-canonical scalar (S ⩾ L).
func (sig *Ed25519Signature) UnmarshalBinary(group curve.Curve, data []byte) error {
	if len(data) != ed25519.SignatureSize {
		return fmt.Errorf("invalid ed25519 signature length: expected %d, got %d", ed25519.SignatureSize, len(data))
	}
	R := group.NewPoint()
	if err := R.UnmarshalBinary(data[:32]); err != nil {
		return fmt.Errorf("failed to unmarshal R: %w", err)
	}
	sBE := make([]byte, 32)
	for i := 0; i < 32; i++ {
		sBE[i] = data[63-i]
	}
	S := group.NewScalar()
	if err := S.UnmarshalBinary(sBE); err != nil {
		return fmt.Errorf("failed to unmarshal S: %w", err)
	}
	sig.R, sig.S = R, S
	return nil
}

// Verify checks the signature with crypto/ed25519 — the same RFC 8032 verifier
// Solana and TON use.
//
// There is deliberately no second, in-house implementation of the verification
// equation. An in-house verifier can only ever prove that we agree with
// ourselves, which is exactly how a signature scheme that is not really Ed25519
// passes its own tests. Verification is cofactorless: crypto/ed25519 recomputes
// R' = [S]B - [k]A and compares its encoding to R byte-for-byte, so the equation
// must hold exactly in the group and not merely up to the cofactor. FROST
// satisfies that, since R, A and [S]B are all torsion-free by construction.
func (sig Ed25519Signature) Verify(public curve.Point, message []byte) bool {
	if public == nil {
		return false
	}
	pub, err := public.MarshalBinary()
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	raw, err := sig.MarshalBinary()
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, message, raw)
}

// SR25519Signature holds an sr25519 (Schnorrkel) compatible signature.
//
// The signature is 64 bytes: R (32 bytes) || s (32 bytes), with the high bit
// of byte 63 set to distinguish sr25519 from Ed25519.
type SR25519Signature struct {
	// Data is the raw 64-byte signature.
	Data [64]byte
	// SigningContext is the application-level signing context (e.g. "substrate").
	SigningContext []byte
}

// Verify checks an sr25519 signature using the Merlin transcript protocol.
//
// The verification equation is: s*G == R + c*Y
// where c = scalar(transcript.extract_bytes("sign:c", 64)).
func (sig SR25519Signature) Verify(public curve.Point, m []byte) bool {
	// Decode R from the first 32 bytes
	R := r255.NewElement()
	if err := R.Decode(sig.Data[:32]); err != nil {
		return false
	}

	// Decode s from the last 32 bytes (strip the schnorrkel marker bit)
	sBytes := make([]byte, 32)
	copy(sBytes, sig.Data[32:])
	sBytes[31] &= 127 // clear the schnorrkel marker bit
	s := r255.NewScalar()
	if err := s.Decode(sBytes); err != nil {
		return false
	}

	// Reconstruct the Merlin transcript to get the same challenge
	groupKeyBytes, _ := public.MarshalBinary()

	t := merlin.NewTranscript("SigningContext")
	t.AppendMessage([]byte(""), sig.SigningContext)
	t.AppendMessage([]byte("sign-bytes"), m)
	t.AppendMessage([]byte("proto-name"), []byte("Schnorr-sig"))
	t.AppendMessage([]byte("sign:pk"), groupKeyBytes)
	t.AppendMessage([]byte("sign:R"), sig.Data[:32])
	challengeBytes := t.ExtractBytes([]byte("sign:c"), 64)
	k := r255.NewScalar().FromUniformBytes(challengeBytes)

	// Verify: s*G == R + k*Y
	// Equivalent: R' = s*G - k*Y, then R' == R
	// Extract the ristretto255 element from the public key via marshal/unmarshal
	yElement := r255.NewElement()
	if err := yElement.Decode(groupKeyBytes); err != nil {
		return false
	}
	negY := r255.NewElement().Negate(yElement)
	Rp := r255.NewElement().VarTimeDoubleScalarBaseMult(k, negY, s)

	return Rp.Equal(R) == 1
}
