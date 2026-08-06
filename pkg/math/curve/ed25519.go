package curve

import (
	"fmt"

	"filippo.io/edwards25519"
	"github.com/cronokirby/saferith"
)

// Ed25519 group order: l = 2^252 + 27742317777372353535851937790883648493
var ed25519OrderNat, _ = new(saferith.Nat).SetHex("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED")
var ed25519Order = saferith.ModulusFromNat(ed25519OrderNat)

// ed25519LMinusOne is L-1 in the little-endian encoding edwards25519 uses.
//
// It exists so we can compute [L]P as [L-1]P + P: edwards25519.Scalar cannot
// represent L itself, since every scalar is reduced mod L and L ≡ 0. This is the
// only way to test subgroup membership with reduced-scalar arithmetic.
// TestEd25519LMinusOne pins the constant by checking [L-1]G + G = O.
var ed25519LMinusOne = func() *edwards25519.Scalar {
	s, err := edwards25519.NewScalar().SetCanonicalBytes([]byte{
		0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
		0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
	})
	if err != nil {
		panic("curve: invalid Ed25519 L-1 constant: " + err.Error())
	}
	return s
}()

// Ed25519 implements the Curve interface for the Ed25519 group.
type Ed25519 struct{}

func (Ed25519) NewPoint() Point {
	return &Ed25519Point{value: edwards25519.NewIdentityPoint()}
}

func (Ed25519) NewBasePoint() Point {
	return &Ed25519Point{value: edwards25519.NewGeneratorPoint()}
}

func (Ed25519) NewScalar() Scalar {
	return &Ed25519Scalar{value: edwards25519.NewScalar()}
}

func (Ed25519) Name() string {
	return "ed25519"
}

func (Ed25519) ScalarBits() int {
	return 253
}

func (Ed25519) SafeScalarBytes() int {
	return 32
}

func (Ed25519) Order() *saferith.Modulus {
	return ed25519Order
}

// Ed25519Scalar wraps filippo.io/edwards25519.Scalar.
//
// The interface requires big-endian byte encoding. edwards25519 uses
// little-endian internally, so marshal/unmarshal reverses byte order.
type Ed25519Scalar struct {
	value *edwards25519.Scalar
}

func ed25519CastScalar(generic Scalar) *Ed25519Scalar {
	out, ok := generic.(*Ed25519Scalar)
	if !ok {
		panic(fmt.Sprintf("failed to convert to Ed25519Scalar: %v", generic))
	}
	return out
}

func (*Ed25519Scalar) Curve() Curve {
	return Ed25519{}
}

func (s *Ed25519Scalar) MarshalBinary() ([]byte, error) {
	le := s.value.Bytes()
	be := make([]byte, 32)
	for i := 0; i < 32; i++ {
		be[i] = le[31-i]
	}
	return be, nil
}

func (s *Ed25519Scalar) UnmarshalBinary(data []byte) error {
	if len(data) != 32 {
		return fmt.Errorf("invalid length for Ed25519 scalar: %d", len(data))
	}
	le := make([]byte, 32)
	for i := 0; i < 32; i++ {
		le[i] = data[31-i]
	}
	_, err := s.value.SetCanonicalBytes(le)
	if err != nil {
		return fmt.Errorf("invalid bytes for Ed25519 scalar: %w", err)
	}
	return nil
}

func (s *Ed25519Scalar) Add(that Scalar) Scalar {
	other := ed25519CastScalar(that)
	s.value.Add(s.value, other.value)
	return s
}

func (s *Ed25519Scalar) Sub(that Scalar) Scalar {
	other := ed25519CastScalar(that)
	s.value.Subtract(s.value, other.value)
	return s
}

func (s *Ed25519Scalar) Negate() Scalar {
	s.value.Negate(s.value)
	return s
}

func (s *Ed25519Scalar) Mul(that Scalar) Scalar {
	other := ed25519CastScalar(that)
	s.value.Multiply(s.value, other.value)
	return s
}

func (s *Ed25519Scalar) Invert() Scalar {
	s.value.Invert(s.value)
	return s
}

func (s *Ed25519Scalar) Equal(that Scalar) bool {
	other := ed25519CastScalar(that)
	return s.value.Equal(other.value) == 1
}

func (s *Ed25519Scalar) IsZero() bool {
	zero := edwards25519.NewScalar()
	return s.value.Equal(zero) == 1
}

func (s *Ed25519Scalar) Set(that Scalar) Scalar {
	other := ed25519CastScalar(that)
	s.value.Set(other.value)
	return s
}

func (s *Ed25519Scalar) SetNat(x *saferith.Nat) Scalar {
	reduced := new(saferith.Nat).Mod(x, ed25519Order)
	beBytes := reduced.Bytes()
	// Pad to 32 bytes big-endian
	padded := make([]byte, 32)
	if len(beBytes) > 0 {
		copy(padded[32-len(beBytes):], beBytes)
	}
	// Convert to little-endian for edwards25519
	le := make([]byte, 32)
	for i := 0; i < 32; i++ {
		le[i] = padded[31-i]
	}
	_, err := s.value.SetCanonicalBytes(le)
	if err != nil {
		// If SetCanonicalBytes fails (shouldn't after mod reduction), fall back to zero
		s.value = edwards25519.NewScalar()
	}
	return s
}

// SetUniformBytes sets the scalar to the reduction mod L of a 64-byte
// little-endian value.
//
// This is the wide reduction RFC 8032 §5.1.6 applies to the SHA-512 challenge
// digest, and is byte-identical to what crypto/ed25519 does when it derives k.
// It is distinct from SetNat, which takes big-endian input (the curve.Scalar
// interface's encoding) and reduces a value that is already at most 32 bytes.
func (s *Ed25519Scalar) SetUniformBytes(b []byte) (*Ed25519Scalar, error) {
	if _, err := s.value.SetUniformBytes(b); err != nil {
		return nil, fmt.Errorf("invalid uniform bytes for Ed25519 scalar: %w", err)
	}
	return s, nil
}

func (s *Ed25519Scalar) Act(that Point) Point {
	other := ed25519CastPoint(that)
	out := &Ed25519Point{value: new(edwards25519.Point)}
	out.value.ScalarMult(s.value, other.value)
	return out
}

func (s *Ed25519Scalar) ActOnBase() Point {
	out := &Ed25519Point{value: new(edwards25519.Point)}
	out.value.ScalarBaseMult(s.value)
	return out
}

func (s *Ed25519Scalar) IsOverHalfOrder() bool {
	be, _ := s.MarshalBinary()
	// Half order (big-endian): order / 2
	// order = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
	// order/2 ≈ 0x080000000000000000000000000000000A6F7CEF517BCE6B2C09318D2E7AE9F7
	halfOrderNat, _ := new(saferith.Nat).SetHex("080000000000000000000000000000000A6F7CEF517BCE6B2C09318D2E7AE9F7")
	halfOrderMod := saferith.ModulusFromNat(halfOrderNat)
	val := new(saferith.Nat).SetBytes(be)
	gt, _, _ := val.CmpMod(halfOrderMod)
	return gt == 1
}

// Ed25519Point wraps filippo.io/edwards25519.Point.
//
// Points are serialized as 32-byte compressed Edwards Y coordinates
// (little-endian Y with sign of X in the top bit), matching the
// standard Ed25519 encoding.
type Ed25519Point struct {
	value *edwards25519.Point
}

func ed25519CastPoint(generic Point) *Ed25519Point {
	out, ok := generic.(*Ed25519Point)
	if !ok {
		panic(fmt.Sprintf("failed to convert to Ed25519Point: %v", generic))
	}
	return out
}

func (*Ed25519Point) Curve() Curve {
	return Ed25519{}
}

func (p *Ed25519Point) MarshalBinary() ([]byte, error) {
	data := make([]byte, 32)
	copy(data, p.value.Bytes())
	return data, nil
}

func (p *Ed25519Point) UnmarshalBinary(data []byte) error {
	if len(data) != 32 {
		return fmt.Errorf("invalid length for Ed25519 point: %d", len(data))
	}
	_, err := p.value.SetBytes(data)
	if err != nil {
		return fmt.Errorf("invalid bytes for Ed25519 point: %w", err)
	}
	if !p.IsPrimeOrder() {
		return fmt.Errorf("Ed25519 point is not in the prime-order subgroup")
	}
	return nil
}

// IsPrimeOrder reports whether p lies in the prime-order subgroup, i.e. [L]p = O.
//
// Edwards25519 has cofactor 8, so a point that decodes successfully may still
// carry a torsion component. No honest party can produce one: every point in
// these protocols is a sum of scalar multiples of the base point. A dishonest
// party can, and torsion is not merely cosmetic — it makes the Schnorr equation
// z*G = R + c*Y unsatisfiable, because the left side is always torsion-free.
// A tainted group key would therefore yield an address that looks valid, accepts
// deposits, and can never be spent from. Enforcing this on decode is what keeps
// that unreachable; see UnmarshalBinary, the single point of entry from the wire.
func (p *Ed25519Point) IsPrimeOrder() bool {
	lp := new(edwards25519.Point).ScalarMult(ed25519LMinusOne, p.value)
	lp.Add(lp, p.value)
	return lp.Equal(edwards25519.NewIdentityPoint()) == 1
}

func (p *Ed25519Point) Add(that Point) Point {
	other := ed25519CastPoint(that)
	out := &Ed25519Point{value: new(edwards25519.Point)}
	out.value.Add(p.value, other.value)
	return out
}

func (p *Ed25519Point) Sub(that Point) Point {
	other := ed25519CastPoint(that)
	out := &Ed25519Point{value: new(edwards25519.Point)}
	out.value.Subtract(p.value, other.value)
	return out
}

func (p *Ed25519Point) Negate() Point {
	out := &Ed25519Point{value: new(edwards25519.Point)}
	out.value.Negate(p.value)
	return out
}

func (p *Ed25519Point) Equal(that Point) bool {
	other := ed25519CastPoint(that)
	return p.value.Equal(other.value) == 1
}

func (p *Ed25519Point) IsIdentity() bool {
	id := edwards25519.NewIdentityPoint()
	return p.value.Equal(id) == 1
}

// XScalar returns nil. Ed25519 does not have a natural x-coordinate
// to scalar mapping used in ECDSA.
func (p *Ed25519Point) XScalar() Scalar {
	return nil
}

// Ensure interfaces are satisfied at compile time.
var (
	_ Curve  = Ed25519{}
	_ Scalar = (*Ed25519Scalar)(nil)
	_ Point  = (*Ed25519Point)(nil)
)
