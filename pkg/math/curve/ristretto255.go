package curve

import (
	"fmt"
	"math/big"

	"github.com/cronokirby/saferith"
	r255 "github.com/gtank/ristretto255"
)

// ristretto255Order is l = 2^252 + 27742317777372353535851937790883648493.
var ristretto255OrderBig = func() *big.Int {
	l := new(big.Int).SetInt64(1)
	l.Lsh(l, 252)
	delta, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	l.Add(l, delta)
	return l
}()

var ristretto255OrderNat = func() *saferith.Nat {
	b := ristretto255OrderBig.Bytes() // big-endian
	return new(saferith.Nat).SetBytes(b)
}()

var ristretto255Order = saferith.ModulusFromNat(ristretto255OrderNat)

// halfOrder for IsOverHalfOrder check.
var ristretto255HalfOrder = new(big.Int).Rsh(ristretto255OrderBig, 1)

// Ristretto255 implements the Curve interface for the ristretto255 prime-order group.
type Ristretto255 struct{}

func (Ristretto255) NewPoint() Point {
	return &Ristretto255Point{value: r255.NewElement().Zero()}
}

func (Ristretto255) NewBasePoint() Point {
	return &Ristretto255Point{value: r255.NewElement().Base()}
}

func (Ristretto255) NewScalar() Scalar {
	return &Ristretto255Scalar{value: r255.NewScalar().Zero()}
}

func (Ristretto255) Name() string {
	return "ristretto255"
}

func (Ristretto255) ScalarBits() int {
	return 253
}

func (Ristretto255) SafeScalarBytes() int {
	return 32
}

func (Ristretto255) Order() *saferith.Modulus {
	return ristretto255Order
}

// --- Ristretto255Scalar ---

// Ristretto255Scalar implements the Scalar interface using ristretto255.Scalar.
type Ristretto255Scalar struct {
	value *r255.Scalar
}

func ristretto255CastScalar(generic Scalar) *Ristretto255Scalar {
	out, ok := generic.(*Ristretto255Scalar)
	if !ok {
		panic(fmt.Sprintf("failed to convert to Ristretto255Scalar: %v", generic))
	}
	return out
}

func (*Ristretto255Scalar) Curve() Curve {
	return Ristretto255{}
}

// MarshalBinary encodes the scalar as 32 big-endian bytes.
// The ristretto255 library uses little-endian internally, so we reverse.
func (s *Ristretto255Scalar) MarshalBinary() ([]byte, error) {
	le := s.value.Encode(nil) // 32 bytes, little-endian
	be := make([]byte, 32)
	for i := 0; i < 32; i++ {
		be[i] = le[31-i]
	}
	return be, nil
}

// UnmarshalBinary decodes 32 big-endian bytes into the scalar.
func (s *Ristretto255Scalar) UnmarshalBinary(data []byte) error {
	if len(data) != 32 {
		return fmt.Errorf("invalid length for ristretto255 scalar: %d", len(data))
	}
	le := make([]byte, 32)
	for i := 0; i < 32; i++ {
		le[i] = data[31-i]
	}
	if err := s.value.Decode(le); err != nil {
		return fmt.Errorf("invalid bytes for ristretto255 scalar: %w", err)
	}
	return nil
}

func (s *Ristretto255Scalar) Add(that Scalar) Scalar {
	other := ristretto255CastScalar(that)
	s.value.Add(s.value, other.value)
	return s
}

func (s *Ristretto255Scalar) Sub(that Scalar) Scalar {
	other := ristretto255CastScalar(that)
	s.value.Subtract(s.value, other.value)
	return s
}

func (s *Ristretto255Scalar) Negate() Scalar {
	s.value.Negate(s.value)
	return s
}

func (s *Ristretto255Scalar) Mul(that Scalar) Scalar {
	other := ristretto255CastScalar(that)
	s.value.Multiply(s.value, other.value)
	return s
}

func (s *Ristretto255Scalar) Invert() Scalar {
	s.value.Invert(s.value)
	return s
}

func (s *Ristretto255Scalar) Equal(that Scalar) bool {
	other := ristretto255CastScalar(that)
	return s.value.Equal(other.value) == 1
}

func (s *Ristretto255Scalar) IsZero() bool {
	return s.value.Equal(r255.NewScalar().Zero()) == 1
}

func (s *Ristretto255Scalar) Set(that Scalar) Scalar {
	other := ristretto255CastScalar(that)
	// Encode + Decode is the only way to copy since Scalar fields are unexported.
	le := other.value.Encode(nil)
	s.value.Decode(le)
	return s
}

func (s *Ristretto255Scalar) SetNat(x *saferith.Nat) Scalar {
	reduced := new(saferith.Nat).Mod(x, ristretto255Order)
	be := reduced.Bytes()
	// Pad to 32 bytes big-endian, then convert to little-endian for Decode.
	padded := make([]byte, 32)
	if len(be) <= 32 {
		copy(padded[32-len(be):], be)
	} else {
		copy(padded, be[len(be)-32:])
	}
	le := make([]byte, 32)
	for i := 0; i < 32; i++ {
		le[i] = padded[31-i]
	}
	s.value.Decode(le)
	return s
}

func (s *Ristretto255Scalar) Act(that Point) Point {
	other := ristretto255CastPoint(that)
	result := r255.NewElement().ScalarMult(s.value, other.value)
	return &Ristretto255Point{value: result}
}

func (s *Ristretto255Scalar) ActOnBase() Point {
	result := r255.NewElement().ScalarBaseMult(s.value)
	return &Ristretto255Point{value: result}
}

func (s *Ristretto255Scalar) IsOverHalfOrder() bool {
	be, _ := s.MarshalBinary()
	val := new(big.Int).SetBytes(be)
	return val.Cmp(ristretto255HalfOrder) > 0
}

// FromUniformBytes sets the scalar from 64 uniform random bytes, reducing mod the group order.
// This is needed for Merlin transcript challenge scalar derivation.
func (s *Ristretto255Scalar) FromUniformBytes(b []byte) *Ristretto255Scalar {
	if len(b) != 64 {
		panic("FromUniformBytes requires exactly 64 bytes")
	}
	s.value.FromUniformBytes(b)
	return s
}

// --- Ristretto255Point ---

// Ristretto255Point implements the Point interface using ristretto255.Element.
type Ristretto255Point struct {
	value *r255.Element
}

func ristretto255CastPoint(generic Point) *Ristretto255Point {
	out, ok := generic.(*Ristretto255Point)
	if !ok {
		panic(fmt.Sprintf("failed to convert to Ristretto255Point: %v", generic))
	}
	return out
}

func (*Ristretto255Point) Curve() Curve {
	return Ristretto255{}
}

// MarshalBinary encodes the point as 32 bytes in ristretto canonical encoding.
func (p *Ristretto255Point) MarshalBinary() ([]byte, error) {
	return p.value.Encode(nil), nil
}

// UnmarshalBinary decodes 32 bytes in ristretto canonical encoding.
func (p *Ristretto255Point) UnmarshalBinary(data []byte) error {
	if len(data) != 32 {
		return fmt.Errorf("invalid length for ristretto255 point: %d", len(data))
	}
	if err := p.value.Decode(data); err != nil {
		return fmt.Errorf("invalid bytes for ristretto255 point: %w", err)
	}
	return nil
}

func (p *Ristretto255Point) Add(that Point) Point {
	other := ristretto255CastPoint(that)
	result := r255.NewElement().Add(p.value, other.value)
	return &Ristretto255Point{value: result}
}

func (p *Ristretto255Point) Sub(that Point) Point {
	other := ristretto255CastPoint(that)
	neg := r255.NewElement().Negate(other.value)
	result := r255.NewElement().Add(p.value, neg)
	return &Ristretto255Point{value: result}
}

func (p *Ristretto255Point) Negate() Point {
	result := r255.NewElement().Negate(p.value)
	return &Ristretto255Point{value: result}
}

func (p *Ristretto255Point) Equal(that Point) bool {
	other := ristretto255CastPoint(that)
	return p.value.Equal(other.value) == 1
}

func (p *Ristretto255Point) IsIdentity() bool {
	identity := r255.NewElement().Zero()
	return p.value.Equal(identity) == 1
}

// XScalar returns nil since ristretto255 is not an ECDSA curve.
func (p *Ristretto255Point) XScalar() Scalar {
	return nil
}

// Ensure interfaces are satisfied at compile time.
var (
	_ Curve  = Ristretto255{}
	_ Scalar = (*Ristretto255Scalar)(nil)
	_ Point  = (*Ristretto255Point)(nil)
)
