package curve

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test Secp256k1 curve implementation
func TestSecp256k1_Curve(t *testing.T) {
	curve := Secp256k1{}

	// Test curve properties
	assert.Equal(t, "secp256k1", curve.Name())
	assert.Equal(t, 256, curve.ScalarBits())
	assert.Equal(t, 32, curve.SafeScalarBytes())

	// Test order
	order := curve.Order()
	assert.NotNil(t, order)
	expectedOrder, _ := new(saferith.Nat).SetHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	assert.Equal(t, expectedOrder.String(), order.Nat().String())
}

// Test point creation
func TestSecp256k1_NewPoint(t *testing.T) {
	curve := Secp256k1{}

	// Test identity point
	p := curve.NewPoint()
	assert.NotNil(t, p)
	assert.True(t, p.IsIdentity())

	// Test base point
	g := curve.NewBasePoint()
	assert.NotNil(t, g)
	assert.False(t, g.IsIdentity())
	assert.Equal(t, curve, g.Curve())
}

// Test scalar creation
func TestSecp256k1_NewScalar(t *testing.T) {
	curve := Secp256k1{}

	// Test zero scalar
	s := curve.NewScalar()
	assert.NotNil(t, s)
	assert.True(t, s.IsZero())
	assert.Equal(t, curve, s.Curve())
}

// Test scalar marshaling
func TestSecp256k1Scalar_MarshalBinary(t *testing.T) {
	curve := Secp256k1{}
	
	// Test zero scalar
	s := curve.NewScalar()
	data, err := s.MarshalBinary()
	require.NoError(t, err)
	assert.Len(t, data, 32)
	assert.Equal(t, make([]byte, 32), data)

	// Test unmarshaling
	s2 := curve.NewScalar()
	err = s2.UnmarshalBinary(data)
	require.NoError(t, err)
	assert.True(t, s.Equal(s2))

	// Test non-zero scalar
	s3 := curve.NewScalar()
	oneBytes := make([]byte, 32)
	oneBytes[31] = 1
	err = s3.UnmarshalBinary(oneBytes)
	require.NoError(t, err)
	assert.False(t, s3.IsZero())

	// Test invalid length
	err = s3.UnmarshalBinary([]byte{1, 2, 3})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid length")

	// Test invalid scalar (larger than order)
	invalidBytes := make([]byte, 32)
	for i := range invalidBytes {
		invalidBytes[i] = 0xFF
	}
	s4 := curve.NewScalar()
	err = s4.UnmarshalBinary(invalidBytes)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid bytes")
}

// Test scalar operations
func TestSecp256k1Scalar_Operations(t *testing.T) {
	curve := Secp256k1{}

	// Create test scalars
	one := curve.NewScalar()
	oneBytes := make([]byte, 32)
	oneBytes[31] = 1
	err := one.UnmarshalBinary(oneBytes)
	require.NoError(t, err)

	two := curve.NewScalar()
	twoBytes := make([]byte, 32)
	twoBytes[31] = 2
	err = two.UnmarshalBinary(twoBytes)
	require.NoError(t, err)

	three := curve.NewScalar()
	threeBytes := make([]byte, 32)
	threeBytes[31] = 3
	err = three.UnmarshalBinary(threeBytes)
	require.NoError(t, err)

	// Test addition
	sum := curve.NewScalar().Set(one).Add(two)
	assert.True(t, sum.Equal(three))

	// Test subtraction
	diff := curve.NewScalar().Set(three).Sub(two)
	assert.True(t, diff.Equal(one))

	// Test multiplication
	six := curve.NewScalar()
	sixBytes := make([]byte, 32)
	sixBytes[31] = 6
	err = six.UnmarshalBinary(sixBytes)
	require.NoError(t, err)

	prod := curve.NewScalar().Set(two).Mul(three)
	assert.True(t, prod.Equal(six))

	// Test negation
	neg := curve.NewScalar().Set(one).Negate()
	zero := curve.NewScalar().Set(one).Add(neg)
	assert.True(t, zero.IsZero())

	// Test inversion
	inv := curve.NewScalar().Set(two).Invert()
	result := curve.NewScalar().Set(two).Mul(inv)
	assert.True(t, result.Equal(one))
}

// Test scalar SetNat
func TestSecp256k1Scalar_SetNat(t *testing.T) {
	curve := Secp256k1{}
	s := curve.NewScalar()

	// Test setting from Nat
	nat := new(saferith.Nat).SetUint64(12345)
	modNat := new(saferith.Nat).Mod(nat, curve.Order())
	s.SetNat(modNat)
	
	data, err := s.MarshalBinary()
	require.NoError(t, err)
	
	// Verify the value is correct
	expected := make([]byte, 32)
	natBytes := nat.Bytes()
	copy(expected[32-len(natBytes):], natBytes)
	assert.Equal(t, expected, data)
}

// Test scalar Act and ActOnBase
func TestSecp256k1Scalar_Act(t *testing.T) {
	curve := Secp256k1{}

	// Test ActOnBase
	s := curve.NewScalar()
	oneBytes := make([]byte, 32)
	oneBytes[31] = 1
	err := s.UnmarshalBinary(oneBytes)
	require.NoError(t, err)

	g := s.ActOnBase()
	assert.NotNil(t, g)
	assert.False(t, g.IsIdentity())
	assert.Equal(t, curve.NewBasePoint(), g)

	// Test Act on point
	two := curve.NewScalar()
	twoBytes := make([]byte, 32)
	twoBytes[31] = 2
	err = two.UnmarshalBinary(twoBytes)
	require.NoError(t, err)

	g2 := two.Act(g)
	assert.NotNil(t, g2)
	assert.False(t, g2.IsIdentity())

	// Verify 2*G = G + G
	gPlusG := curve.NewBasePoint().Add(curve.NewBasePoint())
	assert.True(t, g2.Equal(gPlusG))
}

// Test point marshaling
func TestSecp256k1Point_MarshalBinary(t *testing.T) {
	curve := Secp256k1{}

	// Note: Identity point cannot be marshaled/unmarshaled in compressed format
	// This is a limitation of the compressed point representation

	// Test base point
	g := curve.NewBasePoint()
	data, err := g.MarshalBinary()
	require.NoError(t, err)
	assert.Len(t, data, 33)

	g2 := curve.NewPoint()
	err = g2.UnmarshalBinary(data)
	require.NoError(t, err)
	assert.True(t, g.Equal(g2))

	// Test invalid data length
	p := curve.NewPoint()
	err = p.UnmarshalBinary([]byte{1, 2, 3})
	assert.Error(t, err)
}

// Test point operations
func TestSecp256k1Point_Operations(t *testing.T) {
	curve := Secp256k1{}

	// Create points
	g := curve.NewBasePoint()
	g2 := curve.NewBasePoint().Add(g)
	g3 := g2.Add(g)

	// Test addition
	assert.False(t, g2.Equal(g))
	assert.False(t, g3.Equal(g2))

	// Test subtraction
	diff := g3.Sub(g)
	assert.True(t, diff.Equal(g2))

	// Test negation
	neg := g.Negate()
	zero := g.Add(neg)
	assert.True(t, zero.IsIdentity())

	// Test identity operations
	id := curve.NewPoint()
	sum := g.Add(id)
	assert.True(t, sum.Equal(g))
}

// Test XScalar method
func TestSecp256k1Point_XScalar(t *testing.T) {
	curve := Secp256k1{}

	// Test with base point
	g := curve.NewBasePoint()
	xScalar := g.XScalar()
	assert.NotNil(t, xScalar)
	assert.False(t, xScalar.IsZero())

	// Test with identity (returns zero scalar)
	id := curve.NewPoint()
	xScalar = id.XScalar()
	assert.NotNil(t, xScalar)
	assert.True(t, xScalar.IsZero())

	// Test with another point
	g2 := g.Add(g)
	xScalar2 := g2.XScalar()
	assert.NotNil(t, xScalar2)
	assert.False(t, xScalar.Equal(xScalar2))
}

// Test LiftX method
func TestSecp256k1_LiftX(t *testing.T) {
	curve := Secp256k1{}

	// Get x coordinate from base point
	g := curve.NewBasePoint()
	xScalar := g.XScalar()
	require.NotNil(t, xScalar)

	xBytes, err := xScalar.MarshalBinary()
	require.NoError(t, err)

	// Lift x coordinate back to point
	p, err := curve.LiftX(xBytes)
	require.NoError(t, err)
	assert.NotNil(t, p)

	// The lifted point should have the same x coordinate
	xScalar2 := p.XScalar()
	assert.True(t, xScalar.Equal(xScalar2))

	// Test with invalid x (not on curve)
	invalidX := make([]byte, 32)
	for i := range invalidX {
		invalidX[i] = 0xFF
	}
	_, err = curve.LiftX(invalidX)
	assert.Error(t, err)

	// Test with x that's out of range
	outOfRangeX := make([]byte, 32)
	for i := range outOfRangeX {
		outOfRangeX[i] = 0xFF
	}
	_, err = curve.LiftX(outOfRangeX)
	assert.Error(t, err)
}

// Test panic on wrong scalar type
func TestSecp256k1_CastScalar_Panic(t *testing.T) {
	// Create a mock scalar that doesn't match
	type mockScalar struct {
		Scalar
	}

	defer func() {
		r := recover()
		assert.NotNil(t, r)
		assert.Contains(t, r.(string), "failed to convert to secp256k1Scalar")
	}()

	// This should panic
	secp256k1CastScalar(&mockScalar{})
}

// Test panic on wrong point type
func TestSecp256k1_CastPoint_Panic(t *testing.T) {
	type mockPoint struct {
		Point
	}

	defer func() {
		r := recover()
		assert.NotNil(t, r)
		assert.Contains(t, r.(string), "failed to convert to secp256k1Point")
	}()

	// This should panic
	secp256k1CastPoint(&mockPoint{})
}

// Test random scalar generation
func TestSecp256k1_RandomScalar(t *testing.T) {
	curve := Secp256k1{}

	// Generate random bytes
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	require.NoError(t, err)

	// Create scalar from random bytes (may fail if >= order)
	s := curve.NewScalar()
	err = s.UnmarshalBinary(randomBytes)
	// If it fails, it should be because the value is >= order
	if err != nil {
		assert.Contains(t, err.Error(), "invalid bytes")
	}
}

// Test edge cases
func TestSecp256k1_EdgeCases(t *testing.T) {
	curve := Secp256k1{}

	// Test zero scalar operations
	zero := curve.NewScalar()
	one := curve.NewScalar()
	oneBytes := make([]byte, 32)
	oneBytes[31] = 1
	err := one.UnmarshalBinary(oneBytes)
	require.NoError(t, err)

	// 0 + 1 = 1
	sum := curve.NewScalar().Set(zero).Add(one)
	assert.True(t, sum.Equal(one))

	// 0 * 1 = 0
	prod := curve.NewScalar().Set(zero).Mul(one)
	assert.True(t, prod.IsZero())

	// Test identity point operations
	id := curve.NewPoint()
	g := curve.NewBasePoint()

	// id + G = G
	sum2 := id.Add(g)
	assert.True(t, sum2.Equal(g))

	// Test scalar acting on identity
	result := one.Act(id)
	assert.True(t, result.IsIdentity())
}

// Test compressed point representation
func TestSecp256k1Point_Compressed(t *testing.T) {
	curve := Secp256k1{}

	// Test base point compression
	g := curve.NewBasePoint()
	compressedData, err := g.MarshalBinary()
	require.NoError(t, err)

	// Should be compressed format (33 bytes)
	assert.Len(t, compressedData, 33)
	// First byte should be 0x02 or 0x03 for compressed points
	assert.True(t, compressedData[0] == 0x02 || compressedData[0] == 0x03)

	// Test roundtrip
	g2 := curve.NewPoint()
	err = g2.UnmarshalBinary(compressedData)
	require.NoError(t, err)
	assert.True(t, g.Equal(g2))
}

// Benchmark scalar operations
func BenchmarkSecp256k1Scalar_Add(b *testing.B) {
	curve := Secp256k1{}
	s1 := curve.NewScalar()
	s2 := curve.NewScalar()

	bytes1 := make([]byte, 32)
	bytes1[31] = 123
	s1.UnmarshalBinary(bytes1)

	bytes2 := make([]byte, 32)
	bytes2[31] = 234
	s2.UnmarshalBinary(bytes2)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s1.Add(s2)
	}
}

func BenchmarkSecp256k1Scalar_Mul(b *testing.B) {
	curve := Secp256k1{}
	s1 := curve.NewScalar()
	s2 := curve.NewScalar()

	bytes1 := make([]byte, 32)
	bytes1[31] = 123
	s1.UnmarshalBinary(bytes1)

	bytes2 := make([]byte, 32)
	bytes2[31] = 234
	s2.UnmarshalBinary(bytes2)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s1.Mul(s2)
	}
}

func BenchmarkSecp256k1Point_Add(b *testing.B) {
	curve := Secp256k1{}
	g := curve.NewBasePoint()
	g2 := curve.NewBasePoint().Add(g)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.Add(g2)
	}
}

// Test specific secp256k1 values
func TestSecp256k1_KnownValues(t *testing.T) {
	curve := Secp256k1{}

	// Test known base point coordinates
	g := curve.NewBasePoint()
	_, err := g.MarshalBinary()
	require.NoError(t, err)

	// The x-coordinate of the base point
	expectedX, _ := hex.DecodeString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	
	// For compressed format, check x-coordinate is correct
	// (skip the first byte which is the compression flag)
	xCoord := g.XScalar()
	xBytes, err := xCoord.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, expectedX, xBytes)
}

// Helper function to create scalar from uint64
func scalarFromUint64(curve Curve, val uint64) Scalar {
	s := curve.NewScalar()
	bytes := make([]byte, 32)
	// Convert uint64 to big endian bytes
	for i := 0; i < 8; i++ {
		bytes[31-i] = byte(val >> (8 * i))
	}
	s.UnmarshalBinary(bytes)
	return s
}

// Test more complex scalar arithmetic
func TestSecp256k1Scalar_ComplexArithmetic(t *testing.T) {
	curve := Secp256k1{}

	// Test (a + b) * c = a*c + b*c
	a := scalarFromUint64(curve, 7)
	b := scalarFromUint64(curve, 11)
	c := scalarFromUint64(curve, 13)

	// Left side: (a + b) * c
	aPlusB := curve.NewScalar().Set(a).Add(b)
	left := curve.NewScalar().Set(aPlusB).Mul(c)

	// Right side: a*c + b*c
	ac := curve.NewScalar().Set(a).Mul(c)
	bc := curve.NewScalar().Set(b).Mul(c)
	right := curve.NewScalar().Set(ac).Add(bc)

	assert.True(t, left.Equal(right))

	// Test inverse properties: a * a^(-1) = 1
	aInv := curve.NewScalar().Set(a).Invert()
	one := curve.NewScalar().Set(a).Mul(aInv)
	
	expectedOne := scalarFromUint64(curve, 1)
	assert.True(t, one.Equal(expectedOne))
}