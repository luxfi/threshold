package curve

import (
	"crypto/rand"
	"errors"
	"testing"

	"github.com/cronokirby/saferith"
	r255 "github.com/gtank/ristretto255"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRistretto255_Curve(t *testing.T) {
	c := Ristretto255{}

	assert.Equal(t, "ristretto255", c.Name())
	assert.Equal(t, 253, c.ScalarBits())
	assert.Equal(t, 32, c.SafeScalarBytes())

	order := c.Order()
	assert.NotNil(t, order)

	// l = 2^252 + 27742317777372353535851937790883648493
	expectedHex := "1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED"
	expectedNat, _ := new(saferith.Nat).SetHex(expectedHex)
	assert.Equal(t, expectedNat.String(), order.Nat().String())
}

func TestRistretto255_NewPoint(t *testing.T) {
	c := Ristretto255{}

	// Identity point
	p := c.NewPoint()
	assert.NotNil(t, p)
	assert.True(t, p.IsIdentity())

	// Base point
	g := c.NewBasePoint()
	assert.NotNil(t, g)
	assert.False(t, g.IsIdentity())
	assert.Equal(t, c, g.Curve())
}

func TestRistretto255_NewScalar(t *testing.T) {
	c := Ristretto255{}

	s := c.NewScalar()
	assert.NotNil(t, s)
	assert.True(t, s.IsZero())
	assert.Equal(t, c, s.Curve())
}

func TestRistretto255Scalar_MarshalRoundtrip(t *testing.T) {
	c := Ristretto255{}

	// Zero scalar
	s := c.NewScalar()
	data, err := s.MarshalBinary()
	require.NoError(t, err)
	assert.Len(t, data, 32)
	assert.Equal(t, make([]byte, 32), data)

	s2 := c.NewScalar()
	err = s2.UnmarshalBinary(data)
	require.NoError(t, err)
	assert.True(t, s.Equal(s2))

	// Non-zero scalar (value=1)
	s3 := c.NewScalar()
	oneBytes := make([]byte, 32)
	oneBytes[31] = 1
	err = s3.UnmarshalBinary(oneBytes)
	require.NoError(t, err)
	assert.False(t, s3.IsZero())

	data3, err := s3.MarshalBinary()
	require.NoError(t, err)
	s4 := c.NewScalar()
	err = s4.UnmarshalBinary(data3)
	require.NoError(t, err)
	assert.True(t, s3.Equal(s4))

	// Invalid length
	err = c.NewScalar().UnmarshalBinary([]byte{1, 2, 3})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid length")
}

func TestRistretto255Scalar_Arithmetic(t *testing.T) {
	c := Ristretto255{}

	one := ristretto255ScalarFromUint64(c, 1)
	two := ristretto255ScalarFromUint64(c, 2)
	three := ristretto255ScalarFromUint64(c, 3)
	six := ristretto255ScalarFromUint64(c, 6)

	// Addition: 1 + 2 = 3
	sum := c.NewScalar().Set(one).Add(two)
	assert.True(t, sum.Equal(three))

	// Subtraction: 3 - 2 = 1
	diff := c.NewScalar().Set(three).Sub(two)
	assert.True(t, diff.Equal(one))

	// Multiplication: 2 * 3 = 6
	prod := c.NewScalar().Set(two).Mul(three)
	assert.True(t, prod.Equal(six))

	// Negation: 1 + (-1) = 0
	neg := c.NewScalar().Set(one).Negate()
	zero := c.NewScalar().Set(one).Add(neg)
	assert.True(t, zero.IsZero())

	// Inversion: 2 * 2^-1 = 1
	inv := c.NewScalar().Set(two).Invert()
	result := c.NewScalar().Set(two).Mul(inv)
	assert.True(t, result.Equal(one))
}

func TestRistretto255Scalar_Distributive(t *testing.T) {
	c := Ristretto255{}

	a := ristretto255ScalarFromUint64(c, 7)
	b := ristretto255ScalarFromUint64(c, 11)
	cc := ristretto255ScalarFromUint64(c, 13)

	// (a + b) * c = a*c + b*c
	aPlusB := c.NewScalar().Set(a).Add(b)
	left := c.NewScalar().Set(aPlusB).Mul(cc)

	ac := c.NewScalar().Set(a).Mul(cc)
	bc := c.NewScalar().Set(b).Mul(cc)
	right := c.NewScalar().Set(ac).Add(bc)

	assert.True(t, left.Equal(right))
}

func TestRistretto255Scalar_SetNat(t *testing.T) {
	c := Ristretto255{}

	nat := new(saferith.Nat).SetUint64(12345)
	s := c.NewScalar()
	s.SetNat(nat)

	data, err := s.MarshalBinary()
	require.NoError(t, err)

	expected := make([]byte, 32)
	natBytes := nat.Bytes()
	copy(expected[32-len(natBytes):], natBytes)
	assert.Equal(t, expected, data)
}

func TestRistretto255Scalar_ActOnBase(t *testing.T) {
	c := Ristretto255{}

	// 1 * G = G
	one := ristretto255ScalarFromUint64(c, 1)
	g := one.ActOnBase()
	assert.NotNil(t, g)
	assert.False(t, g.IsIdentity())
	assert.True(t, g.Equal(c.NewBasePoint()))

	// 2 * G = G + G
	two := ristretto255ScalarFromUint64(c, 2)
	g2 := two.ActOnBase()
	gPlusG := c.NewBasePoint().Add(c.NewBasePoint())
	assert.True(t, g2.Equal(gPlusG))
}

func TestRistretto255Scalar_Act(t *testing.T) {
	c := Ristretto255{}

	two := ristretto255ScalarFromUint64(c, 2)
	three := ristretto255ScalarFromUint64(c, 3)

	g := c.NewBasePoint()

	// 2 * (3 * G) = 6 * G
	g3 := three.Act(g)
	g6a := two.Act(g3)

	six := ristretto255ScalarFromUint64(c, 6)
	g6b := six.ActOnBase()

	assert.True(t, g6a.Equal(g6b))

	// scalar * identity = identity
	id := c.NewPoint()
	result := two.Act(id)
	assert.True(t, result.IsIdentity())
}

func TestRistretto255Point_MarshalRoundtrip(t *testing.T) {
	c := Ristretto255{}

	// Base point roundtrip
	g := c.NewBasePoint()
	data, err := g.MarshalBinary()
	require.NoError(t, err)
	assert.Len(t, data, 32)

	g2 := c.NewPoint()
	err = g2.UnmarshalBinary(data)
	require.NoError(t, err)
	assert.True(t, g.Equal(g2))

	// Identity point roundtrip
	id := c.NewPoint()
	data, err = id.MarshalBinary()
	require.NoError(t, err)
	assert.Len(t, data, 32)

	id2 := c.NewPoint()
	err = id2.UnmarshalBinary(data)
	require.NoError(t, err)
	assert.True(t, id.Equal(id2))
	assert.True(t, id2.IsIdentity())

	// Invalid length
	err = c.NewPoint().UnmarshalBinary([]byte{1, 2, 3})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid length")
}

func TestRistretto255Point_Operations(t *testing.T) {
	c := Ristretto255{}

	g := c.NewBasePoint()
	g2 := g.Add(g)
	g3 := g2.Add(g)

	// Points are distinct
	assert.False(t, g.Equal(g2))
	assert.False(t, g2.Equal(g3))

	// Subtraction: 3G - G = 2G
	diff := g3.Sub(g)
	assert.True(t, diff.Equal(g2))

	// Negation: G + (-G) = identity
	neg := g.Negate()
	zero := g.Add(neg)
	assert.True(t, zero.IsIdentity())

	// Identity is additive identity: G + 0 = G
	id := c.NewPoint()
	sum := g.Add(id)
	assert.True(t, sum.Equal(g))
}

func TestRistretto255Point_XScalar(t *testing.T) {
	c := Ristretto255{}

	// XScalar returns nil for ristretto255 (not an ECDSA curve)
	g := c.NewBasePoint()
	assert.Nil(t, g.XScalar())
}

func TestRistretto255_FromUniformBytes(t *testing.T) {
	// FromUniformBytes should produce valid non-zero scalars from 64 random bytes.
	uniform := make([]byte, 64)
	_, err := rand.Read(uniform)
	require.NoError(t, err)

	s := &Ristretto255Scalar{value: r255.NewScalar()}
	s.FromUniformBytes(uniform)
	assert.False(t, s.IsZero())

	// Deterministic: same input produces same output.
	s2 := &Ristretto255Scalar{value: r255.NewScalar()}
	s2.FromUniformBytes(uniform)
	assert.True(t, s.Equal(s2))

	// Different input produces different output (with overwhelming probability).
	uniform2 := make([]byte, 64)
	_, err = rand.Read(uniform2)
	require.NoError(t, err)

	s3 := &Ristretto255Scalar{value: r255.NewScalar()}
	s3.FromUniformBytes(uniform2)
	assert.False(t, s.Equal(s3))
}

func TestRistretto255_FromUniformBytes_PanicOnWrongLen(t *testing.T) {
	defer func() {
		r := recover()
		assert.NotNil(t, r)
	}()

	s := &Ristretto255Scalar{value: r255.NewScalar()}
	s.FromUniformBytes(make([]byte, 32)) // wrong length, should panic
}

func TestRistretto255_IdentityAndZero(t *testing.T) {
	c := Ristretto255{}

	// Zero scalar acting on base gives identity
	zero := c.NewScalar()
	result := zero.ActOnBase()
	assert.True(t, result.IsIdentity())

	// Identity point stays identity after add with identity
	id := c.NewPoint()
	id2 := id.Add(id)
	assert.True(t, id2.IsIdentity())

	// Negation of identity is identity
	negId := id.Negate()
	assert.True(t, negId.IsIdentity())
}

func TestRistretto255_CastScalarPanic(t *testing.T) {
	type mockScalar struct{ Scalar }

	defer func() {
		r := recover()
		assert.NotNil(t, r)
		assert.Contains(t, r.(string), "failed to convert to Ristretto255Scalar")
	}()

	ristretto255CastScalar(&mockScalar{})
}

func TestRistretto255_CastPointPanic(t *testing.T) {
	type mockPoint struct{ Point }

	defer func() {
		r := recover()
		assert.NotNil(t, r)
		assert.Contains(t, r.(string), "failed to convert to Ristretto255Point")
	}()

	ristretto255CastPoint(&mockPoint{})
}

func TestRistretto255_IsOverHalfOrder(t *testing.T) {
	c := Ristretto255{}

	// Small value should not be over half order
	small := ristretto255ScalarFromUint64(c, 1)
	assert.False(t, small.IsOverHalfOrder())

	// Zero should not be over half order
	zero := c.NewScalar()
	assert.False(t, zero.IsOverHalfOrder())
}

func ristretto255ScalarFromUint64(c Ristretto255, val uint64) Scalar {
	s := c.NewScalar()
	bytes := make([]byte, 32)
	for i := 0; i < 8; i++ {
		bytes[31-i] = byte(val >> (8 * i))
	}
	s.UnmarshalBinary(bytes)
	return s
}

// A domain separation tag separates nothing when it is empty, and RFC 9380 §3.1
// requires at least one byte. Over 255 the tag no longer fits the length byte
// that DST' appends, which is what keeps two tags from producing one stream, so
// both ends of the range are refused rather than silently accepted.
func TestRistretto255_HashRefusesATagItCannotSeparateWith(t *testing.T) {
	g := Ristretto255{}
	long := make([]byte, 256)
	for _, dst := range [][]byte{nil, {}, long} {
		if _, err := g.HashToPoint(dst, []byte("msg")); !errors.Is(err, ErrHashLength) {
			t.Errorf("HashToPoint accepted a %d-byte tag: %v", len(dst), err)
		}
		if _, err := g.HashToScalar(dst, []byte("msg")); !errors.Is(err, ErrHashLength) {
			t.Errorf("HashToScalar accepted a %d-byte tag: %v", len(dst), err)
		}
	}
	if _, err := g.HashToPoint(long[:255], []byte("msg")); err != nil {
		t.Errorf("a 255-byte tag was refused: %v", err)
	}
}
