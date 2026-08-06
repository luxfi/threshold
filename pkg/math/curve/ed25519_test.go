package curve

import (
	"encoding/hex"
	"testing"

	"filippo.io/edwards25519"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEd25519_Curve(t *testing.T) {
	c := Ed25519{}

	assert.Equal(t, "ed25519", c.Name())
	assert.Equal(t, 253, c.ScalarBits())
	assert.Equal(t, 32, c.SafeScalarBytes())

	order := c.Order()
	assert.NotNil(t, order)
	expectedOrder, _ := new(saferith.Nat).SetHex("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED")
	assert.Equal(t, expectedOrder.String(), order.Nat().String())
}

func TestEd25519_NewPoint(t *testing.T) {
	c := Ed25519{}

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

func TestEd25519_NewScalar(t *testing.T) {
	c := Ed25519{}

	s := c.NewScalar()
	assert.NotNil(t, s)
	assert.True(t, s.IsZero())
	assert.Equal(t, c, s.Curve())
}

func TestEd25519Scalar_MarshalBinary(t *testing.T) {
	c := Ed25519{}

	// Zero scalar
	s := c.NewScalar()
	data, err := s.MarshalBinary()
	require.NoError(t, err)
	assert.Len(t, data, 32)
	assert.Equal(t, make([]byte, 32), data)

	// Roundtrip
	s2 := c.NewScalar()
	err = s2.UnmarshalBinary(data)
	require.NoError(t, err)
	assert.True(t, s.Equal(s2))

	// Non-zero scalar (value = 1, big-endian)
	s3 := c.NewScalar()
	oneBytes := make([]byte, 32)
	oneBytes[31] = 1
	err = s3.UnmarshalBinary(oneBytes)
	require.NoError(t, err)
	assert.False(t, s3.IsZero())

	// Roundtrip non-zero
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

	// Invalid scalar (>= order)
	invalidBytes := make([]byte, 32)
	for i := range invalidBytes {
		invalidBytes[i] = 0xFF
	}
	err = c.NewScalar().UnmarshalBinary(invalidBytes)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid bytes")
}

func TestEd25519Scalar_Operations(t *testing.T) {
	c := Ed25519{}

	one := ed25519ScalarFromUint64(c, 1)
	two := ed25519ScalarFromUint64(c, 2)
	three := ed25519ScalarFromUint64(c, 3)
	six := ed25519ScalarFromUint64(c, 6)

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

	// Inversion: 2 * 2^(-1) = 1
	inv := c.NewScalar().Set(two).Invert()
	result := c.NewScalar().Set(two).Mul(inv)
	assert.True(t, result.Equal(one))
}

func TestEd25519Scalar_SetNat(t *testing.T) {
	c := Ed25519{}
	s := c.NewScalar()

	nat := new(saferith.Nat).SetUint64(12345)
	s.SetNat(nat)

	data, err := s.MarshalBinary()
	require.NoError(t, err)

	expected := make([]byte, 32)
	natBytes := nat.Bytes()
	copy(expected[32-len(natBytes):], natBytes)
	assert.Equal(t, expected, data)
}

func TestEd25519Scalar_ActOnBase(t *testing.T) {
	c := Ed25519{}

	// 1 * G = G
	one := ed25519ScalarFromUint64(c, 1)
	g := one.ActOnBase()
	assert.NotNil(t, g)
	assert.False(t, g.IsIdentity())
	assert.True(t, g.Equal(c.NewBasePoint()))

	// 2 * G = G + G
	two := ed25519ScalarFromUint64(c, 2)
	g2 := two.ActOnBase()
	gPlusG := c.NewBasePoint().Add(c.NewBasePoint())
	assert.True(t, g2.Equal(gPlusG))
}

func TestEd25519Scalar_Act(t *testing.T) {
	c := Ed25519{}

	two := ed25519ScalarFromUint64(c, 2)
	g := c.NewBasePoint()

	// 2 * G via Act
	g2 := two.Act(g)
	assert.NotNil(t, g2)
	assert.False(t, g2.IsIdentity())

	// Should equal G + G
	gPlusG := g.Add(g)
	assert.True(t, g2.Equal(gPlusG))

	// Scalar acting on identity gives identity
	one := ed25519ScalarFromUint64(c, 1)
	id := c.NewPoint()
	result := one.Act(id)
	assert.True(t, result.IsIdentity())
}

func TestEd25519Point_MarshalBinary(t *testing.T) {
	c := Ed25519{}

	// Identity point roundtrip
	id := c.NewPoint()
	data, err := id.MarshalBinary()
	require.NoError(t, err)
	assert.Len(t, data, 32)

	id2 := c.NewPoint()
	// Need to initialize the inner point before unmarshal
	err = id2.UnmarshalBinary(data)
	require.NoError(t, err)
	assert.True(t, id.Equal(id2))

	// Base point roundtrip
	g := c.NewBasePoint()
	gData, err := g.MarshalBinary()
	require.NoError(t, err)
	assert.Len(t, gData, 32)

	g2 := c.NewPoint()
	err = g2.UnmarshalBinary(gData)
	require.NoError(t, err)
	assert.True(t, g.Equal(g2))

	// Invalid data length
	err = c.NewPoint().UnmarshalBinary([]byte{1, 2, 3})
	assert.Error(t, err)
}

func TestEd25519Point_Operations(t *testing.T) {
	c := Ed25519{}

	g := c.NewBasePoint()
	g2 := g.Add(g)
	g3 := g2.Add(g)

	// Addition produces different points
	assert.False(t, g2.Equal(g))
	assert.False(t, g3.Equal(g2))

	// Subtraction: 3G - G = 2G
	diff := g3.Sub(g)
	assert.True(t, diff.Equal(g2))

	// Negation: G + (-G) = identity
	neg := g.Negate()
	zero := g.Add(neg)
	assert.True(t, zero.IsIdentity())

	// Identity + G = G
	id := c.NewPoint()
	sum := id.Add(g)
	assert.True(t, sum.Equal(g))
}

func TestEd25519Point_XScalar(t *testing.T) {
	c := Ed25519{}

	// Ed25519 does not support XScalar
	g := c.NewBasePoint()
	assert.Nil(t, g.XScalar())
}

func TestEd25519_OrderTimesBaseIsIdentity(t *testing.T) {
	c := Ed25519{}

	// n * G = identity where n is the group order
	orderScalar := c.NewScalar()
	orderScalar.SetNat(ed25519Order.Nat())

	// After mod reduction, order mod order = 0
	assert.True(t, orderScalar.IsZero())

	// 0 * G = identity
	result := orderScalar.ActOnBase()
	assert.True(t, result.IsIdentity())
}

func TestEd25519Scalar_ComplexArithmetic(t *testing.T) {
	c := Ed25519{}

	a := ed25519ScalarFromUint64(c, 7)
	b := ed25519ScalarFromUint64(c, 11)
	cc := ed25519ScalarFromUint64(c, 13)

	// (a + b) * c = a*c + b*c
	aPlusB := c.NewScalar().Set(a).Add(b)
	left := c.NewScalar().Set(aPlusB).Mul(cc)

	ac := c.NewScalar().Set(a).Mul(cc)
	bc := c.NewScalar().Set(b).Mul(cc)
	right := c.NewScalar().Set(ac).Add(bc)

	assert.True(t, left.Equal(right))

	// a * a^(-1) = 1
	aInv := c.NewScalar().Set(a).Invert()
	one := c.NewScalar().Set(a).Mul(aInv)

	expectedOne := ed25519ScalarFromUint64(c, 1)
	assert.True(t, one.Equal(expectedOne))
}

func TestEd25519_PointScalarConsistency(t *testing.T) {
	c := Ed25519{}

	// (a + b) * G = a*G + b*G
	a := ed25519ScalarFromUint64(c, 42)
	b := ed25519ScalarFromUint64(c, 58)

	aPlusB := c.NewScalar().Set(a).Add(b)
	left := aPlusB.ActOnBase()

	aG := a.ActOnBase()
	bG := b.ActOnBase()
	right := aG.Add(bG)

	assert.True(t, left.Equal(right))
}

func TestEd25519_CastScalar_Panic(t *testing.T) {
	type mockScalar struct{ Scalar }

	defer func() {
		r := recover()
		assert.NotNil(t, r)
		assert.Contains(t, r.(string), "failed to convert to Ed25519Scalar")
	}()

	ed25519CastScalar(&mockScalar{})
}

func TestEd25519_CastPoint_Panic(t *testing.T) {
	type mockPoint struct{ Point }

	defer func() {
		r := recover()
		assert.NotNil(t, r)
		assert.Contains(t, r.(string), "failed to convert to Ed25519Point")
	}()

	ed25519CastPoint(&mockPoint{})
}

func TestEd25519_FromHash(t *testing.T) {
	c := Ed25519{}

	// FromHash should produce a valid scalar
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i)
	}

	s := FromHash(c, hash)
	assert.NotNil(t, s)
	assert.False(t, s.IsZero())
}

// helper
func ed25519ScalarFromUint64(c Curve, val uint64) Scalar {
	s := c.NewScalar()
	bytes := make([]byte, 32)
	for i := 0; i < 8; i++ {
		bytes[31-i] = byte(val >> (8 * i))
	}
	_ = s.UnmarshalBinary(bytes)
	return s
}

func BenchmarkEd25519Scalar_Add(b *testing.B) {
	c := Ed25519{}
	s1 := ed25519ScalarFromUint64(c, 123)
	s2 := ed25519ScalarFromUint64(c, 234)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s1.Add(s2)
	}
}

func BenchmarkEd25519Scalar_Mul(b *testing.B) {
	c := Ed25519{}
	s1 := ed25519ScalarFromUint64(c, 123)
	s2 := ed25519ScalarFromUint64(c, 234)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s1.Mul(s2)
	}
}

func BenchmarkEd25519Point_Add(b *testing.B) {
	c := Ed25519{}
	g := c.NewBasePoint()
	g2 := c.NewBasePoint().Add(g)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.Add(g2)
	}
}

// TestEd25519LMinusOne pins the ed25519LMinusOne constant.
//
// It is the one value in this file that cannot be checked by inspection, and
// everything the subgroup check decides depends on it being exactly L-1.
func TestEd25519LMinusOne(t *testing.T) {
	// [L-1]G + G = [L]G = O, and only L-1 has that property.
	g := edwards25519.NewGeneratorPoint()
	lg := new(edwards25519.Point).ScalarMult(ed25519LMinusOne, g)
	lg.Add(lg, g)
	assert.Equal(t, 1, lg.Equal(edwards25519.NewIdentityPoint()),
		"[L-1]G + G must be the identity")

	// It also must not be L-2: [L-2]G + G = -G != O.
	lg2 := new(edwards25519.Point).ScalarMult(ed25519LMinusOne, g)
	assert.Equal(t, 1, lg2.Equal(new(edwards25519.Point).Negate(g)),
		"[L-1]G must be -G")
}

// TestEd25519Point_SubgroupCheck covers the cofactor-8 hazard: a point can be on
// the curve, decode cleanly, and still carry a torsion component that makes the
// Schnorr equation unsatisfiable.
func TestEd25519Point_SubgroupCheck(t *testing.T) {
	c := Ed25519{}

	// The canonical small-order points of edwards25519 (orders 2, 4 and 8).
	// Each is a valid curve point, so edwards25519.SetBytes accepts them all.
	smallOrder := []string{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // order 2
		"0000000000000000000000000000000000000000000000000000000000000000", // order 4
		"0000000000000000000000000000000000000000000000000000000000000080", // order 4
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order 8
	}
	for _, h := range smallOrder {
		data, err := hex.DecodeString(h)
		require.NoError(t, err)

		// Sanity: the raw curve decoder does accept it, so the subgroup check is
		// doing real work rather than duplicating an existing validation.
		_, err = new(edwards25519.Point).SetBytes(data)
		require.NoError(t, err, "%s should be a valid curve point", h)

		assert.Error(t, c.NewPoint().UnmarshalBinary(data),
			"small-order point %s must be rejected", h)
	}

	// The identity is in the prime-order subgroup ([L]O = O) and must still
	// decode: keygen refresh relies on decoding identity constants.
	identity, err := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")
	require.NoError(t, err)
	assert.NoError(t, c.NewPoint().UnmarshalBinary(identity))
	assert.True(t, c.NewPoint().(*Ed25519Point).IsPrimeOrder())

	// Honest points round-trip.
	for _, p := range []Point{c.NewBasePoint(), c.NewBasePoint().Add(c.NewBasePoint())} {
		data, err := p.MarshalBinary()
		require.NoError(t, err)
		assert.NoError(t, c.NewPoint().UnmarshalBinary(data))
		assert.True(t, p.(*Ed25519Point).IsPrimeOrder())
	}
}
