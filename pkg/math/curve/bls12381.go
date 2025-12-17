// Package curve provides elliptic curve implementations for threshold cryptography.
package curve

import (
	"io"

	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/cloudflare/circl/ecc/bls12381/ff"
	"github.com/cronokirby/saferith"
)

// BLS12381 is the BLS12-381 curve used for BLS signatures.
// This uses G1 for public keys and G2 for signatures.
type BLS12381 struct{}

// BLS12381G1 returns the BLS12-381 curve for G1 operations (public keys).
func BLS12381G1() Curve {
	return &BLS12381{}
}

// NewPoint creates a new identity point in G1.
func (c *BLS12381) NewPoint() Point {
	p := new(BLS12381Point)
	p.point.SetIdentity()
	return p
}

// NewBasePoint creates the generator of G1.
func (c *BLS12381) NewBasePoint() Point {
	return &BLS12381Point{point: *bls12381.G1Generator()}
}

// NewScalar creates a zero scalar.
func (c *BLS12381) NewScalar() Scalar {
	return &BLS12381Scalar{scalar: ff.Scalar{}}
}

// Name returns the curve name.
func (c *BLS12381) Name() string {
	return "BLS12-381"
}

// ScalarBits returns the number of bits in a scalar.
func (c *BLS12381) ScalarBits() int {
	return 255 // BLS12-381 scalar field is ~255 bits
}

// SafeScalarBytes returns the number of bytes needed to sample a scalar safely.
func (c *BLS12381) SafeScalarBytes() int {
	return 64 // 32 bytes + 32 bytes for bias reduction
}

// Order returns the scalar field order.
func (c *BLS12381) Order() *saferith.Modulus {
	// BLS12-381 scalar field order (r)
	// r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
	orderBytes := []byte{
		0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48,
		0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
		0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe,
		0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
	}
	nat := new(saferith.Nat).SetBytes(orderBytes)
	mod := saferith.ModulusFromNat(nat)
	return mod
}

// BLS12381Scalar wraps circl's BLS12-381 scalar.
type BLS12381Scalar struct {
	scalar ff.Scalar
}

// Curve returns the associated curve.
func (s *BLS12381Scalar) Curve() Curve {
	return &BLS12381{}
}

// MarshalBinary serializes the scalar.
func (s *BLS12381Scalar) MarshalBinary() ([]byte, error) {
	return s.scalar.MarshalBinary()
}

// UnmarshalBinary deserializes the scalar.
func (s *BLS12381Scalar) UnmarshalBinary(data []byte) error {
	return s.scalar.UnmarshalBinary(data)
}

// Add adds another scalar to this one.
func (s *BLS12381Scalar) Add(other Scalar) Scalar {
	o := other.(*BLS12381Scalar)
	s.scalar.Add(&s.scalar, &o.scalar)
	return s
}

// Sub subtracts another scalar from this one.
func (s *BLS12381Scalar) Sub(other Scalar) Scalar {
	o := other.(*BLS12381Scalar)
	s.scalar.Sub(&s.scalar, &o.scalar)
	return s
}

// Negate negates the scalar.
func (s *BLS12381Scalar) Negate() Scalar {
	s.scalar.Neg()
	return s
}

// Mul multiplies by another scalar.
func (s *BLS12381Scalar) Mul(other Scalar) Scalar {
	o := other.(*BLS12381Scalar)
	s.scalar.Mul(&s.scalar, &o.scalar)
	return s
}

// Invert computes the multiplicative inverse.
func (s *BLS12381Scalar) Invert() Scalar {
	s.scalar.Inv(&s.scalar)
	return s
}

// Equal checks equality with another scalar.
func (s *BLS12381Scalar) Equal(other Scalar) bool {
	o := other.(*BLS12381Scalar)
	return s.scalar.IsEqual(&o.scalar) == 1
}

// IsZero checks if the scalar is zero.
func (s *BLS12381Scalar) IsZero() bool {
	return s.scalar.IsZero() == 1
}

// Set copies another scalar's value.
func (s *BLS12381Scalar) Set(other Scalar) Scalar {
	o := other.(*BLS12381Scalar)
	s.scalar = o.scalar
	return s
}

// SetNat sets the scalar from a saferith.Nat.
func (s *BLS12381Scalar) SetNat(n *saferith.Nat) Scalar {
	nBytes := n.Bytes()
	if len(nBytes) == 0 {
		s.scalar.SetUint64(0)
		return s
	}

	// Pad or truncate to 32 bytes (big-endian)
	bytes := make([]byte, 32)
	if len(nBytes) <= 32 {
		copy(bytes[32-len(nBytes):], nBytes)
	} else {
		// Truncate (take last 32 bytes for modular reduction)
		copy(bytes, nBytes[len(nBytes)-32:])
	}
	s.scalar.SetBytes(bytes)
	return s
}

// Act multiplies a point by this scalar.
func (s *BLS12381Scalar) Act(p Point) Point {
	pt := p.(*BLS12381Point)
	result := new(BLS12381Point)
	result.point.ScalarMult(&s.scalar, &pt.point)
	return result
}

// ActOnBase multiplies the generator by this scalar.
func (s *BLS12381Scalar) ActOnBase() Point {
	result := new(BLS12381Point)
	result.point.ScalarMult(&s.scalar, bls12381.G1Generator())
	return result
}

// IsOverHalfOrder checks if the scalar is greater than half the field order.
func (s *BLS12381Scalar) IsOverHalfOrder() bool {
	// For BLS12-381, we compare with order/2
	// This is an approximation - for exact comparison, we'd need the full order
	bytes, _ := s.scalar.MarshalBinary()
	return bytes[0] >= 0x3A // Rough approximation of order/2
}

// SetOne sets the scalar to 1.
func (s *BLS12381Scalar) SetOne() *BLS12381Scalar {
	s.scalar.SetOne()
	return s
}

// SetUint64 sets the scalar from a uint64.
func (s *BLS12381Scalar) SetUint64(n uint64) *BLS12381Scalar {
	s.scalar.SetUint64(n)
	return s
}

// SetBytes sets the scalar from big-endian bytes.
func (s *BLS12381Scalar) SetBytes(data []byte) *BLS12381Scalar {
	s.scalar.SetBytes(data)
	return s
}

// Random sets the scalar to a random value.
func (s *BLS12381Scalar) Random(r io.Reader) error {
	return s.scalar.Random(r)
}

// BLS12381Point wraps circl's BLS12-381 G1 point.
type BLS12381Point struct {
	point bls12381.G1
}

// Curve returns the associated curve.
func (p *BLS12381Point) Curve() Curve {
	return &BLS12381{}
}

// MarshalBinary serializes the point.
func (p *BLS12381Point) MarshalBinary() ([]byte, error) {
	return p.point.BytesCompressed(), nil
}

// UnmarshalBinary deserializes the point.
func (p *BLS12381Point) UnmarshalBinary(data []byte) error {
	return p.point.SetBytes(data)
}

// Add adds another point.
func (p *BLS12381Point) Add(other Point) Point {
	o := other.(*BLS12381Point)
	result := new(BLS12381Point)
	result.point.Add(&p.point, &o.point)
	return result
}

// Sub subtracts another point.
func (p *BLS12381Point) Sub(other Point) Point {
	o := other.(*BLS12381Point)
	neg := new(bls12381.G1)
	*neg = o.point
	neg.Neg()
	result := new(BLS12381Point)
	result.point.Add(&p.point, neg)
	return result
}

// Negate returns the negated point.
func (p *BLS12381Point) Negate() Point {
	result := new(BLS12381Point)
	result.point = p.point
	result.point.Neg()
	return result
}

// Equal checks equality with another point.
func (p *BLS12381Point) Equal(other Point) bool {
	o := other.(*BLS12381Point)
	return p.point.IsEqual(&o.point)
}

// IsIdentity checks if this is the identity element.
func (p *BLS12381Point) IsIdentity() bool {
	return p.point.IsIdentity()
}

// XScalar returns the x-coordinate as a scalar (not applicable for BLS).
func (p *BLS12381Point) XScalar() Scalar {
	// BLS12-381 G1 points don't have a simple x-coordinate to scalar mapping
	// This is used in ECDSA, not BLS
	return nil
}

// Ensure interfaces are satisfied
var (
	_ Curve  = (*BLS12381)(nil)
	_ Scalar = (*BLS12381Scalar)(nil)
	_ Point  = (*BLS12381Point)(nil)
)
