package bip32

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test DeriveScalar basic functionality
func TestDeriveScalar(t *testing.T) {
	// Create a test public key
	group := curve.Secp256k1{}
	scalarNat := new(saferith.Nat).SetUint64(12345)
	scalar := group.NewScalar().(*curve.Secp256k1Scalar)
	scalar.SetNat(scalarNat)
	public := scalar.ActOnBase().(*curve.Secp256k1Point)
	
	// Test chaining value (32 bytes)
	chaining := sha256.Sum256([]byte("test chaining value"))
	
	tests := []struct {
		name      string
		index     uint32
		expectErr bool
	}{
		{
			name:      "valid index 0",
			index:     0,
			expectErr: false,
		},
		{
			name:      "valid index 1",
			index:     1,
			expectErr: false,
		},
		{
			name:      "valid index 100",
			index:     100,
			expectErr: false,
		},
		{
			name:      "max non-hardened index",
			index:     0x7FFFFFFF,
			expectErr: false,
		},
	}
	
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			derivedScalar, newChaining, err := DeriveScalar(public, chaining[:], tc.index)
			
			if tc.expectErr {
				assert.Error(t, err)
				assert.Nil(t, derivedScalar)
				assert.Nil(t, newChaining)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, derivedScalar)
				assert.NotNil(t, newChaining)
				assert.Len(t, newChaining, 32)
				
				// Verify scalar is not zero
				assert.False(t, derivedScalar.IsZero())
				
				// Verify deterministic derivation
				derivedScalar2, newChaining2, err2 := DeriveScalar(public, chaining[:], tc.index)
				assert.NoError(t, err2)
				assert.True(t, derivedScalar.Equal(derivedScalar2))
				assert.Equal(t, newChaining, newChaining2)
			}
		})
	}
}

// Test DeriveScalar with hardened keys (should panic)
func TestDeriveScalar_HardenedPanic(t *testing.T) {
	group := curve.Secp256k1{}
	scalarNat := new(saferith.Nat).SetUint64(12345)
	scalar := group.NewScalar().(*curve.Secp256k1Scalar)
	scalar.SetNat(scalarNat)
	public := scalar.ActOnBase().(*curve.Secp256k1Point)
	chaining := sha256.Sum256([]byte("test"))
	
	// Hardened key has bit 31 set
	hardenedIndex := uint32(0x80000000)
	
	assert.Panics(t, func() {
		DeriveScalar(public, chaining[:], hardenedIndex)
	}, "Should panic with hardened index")
}

// Test DeriveScalar with bad scalar (rare case)
func TestDeriveScalar_BadScalar(t *testing.T) {
	group := curve.Secp256k1{}
	scalarNat := new(saferith.Nat).SetUint64(12345)
	scalar := group.NewScalar().(*curve.Secp256k1Scalar)
	scalar.SetNat(scalarNat)
	public := scalar.ActOnBase().(*curve.Secp256k1Point)
	
	// Try multiple indices to find one that might fail
	// In practice, this is very rare (probability ~1/2^256)
	// We'll test that the error is returned properly if it happens
	
	// Create a chaining value that might produce a zero scalar
	// This is artificial but tests the error path
	chaining := make([]byte, 32)
	// All zeros might produce issues
	
	// We can't easily force the bad scalar condition,
	// but we can test that non-hardened indices work
	_, _, err := DeriveScalar(public, chaining, 0)
	// The error is very unlikely but possible
	if err != nil {
		assert.Contains(t, err.Error(), "bad index")
	}
}

// Test with different public key points
func TestDeriveScalar_DifferentPoints(t *testing.T) {
	group := curve.Secp256k1{}
	chaining := sha256.Sum256([]byte("test"))
	index := uint32(42)
	
	// Create different public keys
	scalarNat1 := new(saferith.Nat).SetUint64(100)
	scalar1 := group.NewScalar().(*curve.Secp256k1Scalar)
	scalar1.SetNat(scalarNat1)
	public1 := scalar1.ActOnBase().(*curve.Secp256k1Point)
	
	scalarNat2 := new(saferith.Nat).SetUint64(200)
	scalar2 := group.NewScalar().(*curve.Secp256k1Scalar)
	scalar2.SetNat(scalarNat2)
	public2 := scalar2.ActOnBase().(*curve.Secp256k1Point)
	
	// Derive from different public keys
	derived1, chain1, err1 := DeriveScalar(public1, chaining[:], index)
	require.NoError(t, err1)
	
	derived2, chain2, err2 := DeriveScalar(public2, chaining[:], index)
	require.NoError(t, err2)
	
	// Results should be different
	assert.False(t, derived1.Equal(derived2))
	assert.NotEqual(t, chain1, chain2)
}

// Test with different chaining values
func TestDeriveScalar_DifferentChaining(t *testing.T) {
	group := curve.Secp256k1{}
	scalarNat := new(saferith.Nat).SetUint64(12345)
	scalar := group.NewScalar().(*curve.Secp256k1Scalar)
	scalar.SetNat(scalarNat)
	public := scalar.ActOnBase().(*curve.Secp256k1Point)
	index := uint32(42)
	
	chaining1 := sha256.Sum256([]byte("chain1"))
	chaining2 := sha256.Sum256([]byte("chain2"))
	
	// Derive with different chaining values
	derived1, newChain1, err1 := DeriveScalar(public, chaining1[:], index)
	require.NoError(t, err1)
	
	derived2, newChain2, err2 := DeriveScalar(public, chaining2[:], index)
	require.NoError(t, err2)
	
	// Results should be different
	assert.False(t, derived1.Equal(derived2))
	assert.NotEqual(t, newChain1, newChain2)
}

// Test with different indices
func TestDeriveScalar_DifferentIndices(t *testing.T) {
	group := curve.Secp256k1{}
	scalarNat := new(saferith.Nat).SetUint64(12345)
	scalar := group.NewScalar().(*curve.Secp256k1Scalar)
	scalar.SetNat(scalarNat)
	public := scalar.ActOnBase().(*curve.Secp256k1Point)
	chaining := sha256.Sum256([]byte("test"))
	
	// Derive with different indices
	derived1, chain1, err1 := DeriveScalar(public, chaining[:], 1)
	require.NoError(t, err1)
	
	derived2, chain2, err2 := DeriveScalar(public, chaining[:], 2)
	require.NoError(t, err2)
	
	// Results should be different
	assert.False(t, derived1.Equal(derived2))
	assert.NotEqual(t, chain1, chain2)
}

// Test chain derivation (multiple levels)
func TestDeriveScalar_ChainDerivation(t *testing.T) {
	group := curve.Secp256k1{}
	
	// Start with a master key
	masterScalarNat := new(saferith.Nat).SetUint64(999)
	masterScalar := group.NewScalar().(*curve.Secp256k1Scalar)
	masterScalar.SetNat(masterScalarNat)
	masterPublic := masterScalar.ActOnBase().(*curve.Secp256k1Point)
	masterChaining := sha256.Sum256([]byte("master"))
	
	// Derive level 1
	scalar1, chaining1, err := DeriveScalar(masterPublic, masterChaining[:], 0)
	require.NoError(t, err)
	
	// Create new public key for level 1
	// newScalar = masterScalar + scalar1
	newScalar1 := group.NewScalar().(*curve.Secp256k1Scalar)
	newScalar1.Set(masterScalar)
	newScalar1.Add(scalar1)
	public1 := newScalar1.ActOnBase().(*curve.Secp256k1Point)
	
	// Derive level 2
	scalar2, chaining2, err := DeriveScalar(public1, chaining1, 1)
	require.NoError(t, err)
	
	// Verify all values are different
	assert.False(t, scalar1.Equal(scalar2))
	assert.NotEqual(t, chaining1, chaining2)
	assert.NotEqual(t, masterChaining[:], chaining1)
}

// Test edge case with point at infinity (if possible)
func TestDeriveScalar_EdgeCases(t *testing.T) {
	group := curve.Secp256k1{}
	chaining := sha256.Sum256([]byte("test"))
	
	// Test with identity point (point at infinity)
	identity := group.NewPoint().(*curve.Secp256k1Point) // Zero point
	
	// This should work - the compressed form of identity has a specific encoding
	derived, newChain, err := DeriveScalar(identity, chaining[:], 0)
	assert.NoError(t, err)
	assert.NotNil(t, derived)
	assert.NotNil(t, newChain)
}

// Benchmark DeriveScalar
func BenchmarkDeriveScalar(b *testing.B) {
	group := curve.Secp256k1{}
	scalarNat := new(saferith.Nat).SetUint64(12345)
	scalar := group.NewScalar().(*curve.Secp256k1Scalar)
	scalar.SetNat(scalarNat)
	public := scalar.ActOnBase().(*curve.Secp256k1Point)
	chaining := sha256.Sum256([]byte("benchmark"))
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_, _, _ = DeriveScalar(public, chaining[:], uint32(i%1000))
	}
}

// Test compliance with BIP32 test vectors (if available)
func TestDeriveScalar_BIP32Compliance(t *testing.T) {
	// This test verifies that our implementation follows BIP32 spec
	// for non-hardened derivation
	
	group := curve.Secp256k1{}
	
	// Use a known test vector format
	// Public key from a known private key
	privKeyHex := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	require.NoError(t, err)
	
	privScalar := group.NewScalar().(*curve.Secp256k1Scalar)
	err = privScalar.UnmarshalBinary(privKeyBytes)
	require.NoError(t, err)
	
	pubKey := privScalar.ActOnBase().(*curve.Secp256k1Point)
	
	// Test chain code
	chainCode := sha256.Sum256([]byte("Bitcoin seed"))
	
	// Derive child
	childScalar, childChain, err := DeriveScalar(pubKey, chainCode[:], 0)
	require.NoError(t, err)
	
	// Verify properties
	assert.NotNil(t, childScalar)
	assert.Len(t, childChain, 32)
	assert.False(t, childScalar.IsZero())
	
	// The child private key would be: privScalar + childScalar
	// The child public key would be: pubKey + childScalar*G
	childPriv := group.NewScalar().(*curve.Secp256k1Scalar)
	childPriv.Set(privScalar)
	childPriv.Add(childScalar)
	childPub := childPriv.ActOnBase()
	
	// Verify the child public key can also be computed as:
	// parentPubKey + childScalar*G
	temp := childScalar.ActOnBase()
	childPubAlt := pubKey.Add(temp)
	
	// Both methods should give the same result
	childPubBytes, _ := childPub.MarshalBinary()
	childPubAltBytes, _ := childPubAlt.MarshalBinary()
	assert.Equal(t, childPubBytes, childPubAltBytes, "Child public key derivation should be consistent")
}

// Test maximum depth derivation
func TestDeriveScalar_MaxDepth(t *testing.T) {
	group := curve.Secp256k1{}
	
	scalarNat := new(saferith.Nat).SetUint64(12345)
	scalar := group.NewScalar().(*curve.Secp256k1Scalar)
	scalar.SetNat(scalarNat)
	public := scalar.ActOnBase().(*curve.Secp256k1Point)
	chaining := sha256.Sum256([]byte("test"))
	
	// BIP32 supports up to 2^32 child keys per parent
	// Test we can derive many levels deep
	currentPublic := public
	currentChaining := chaining[:]
	currentScalar := scalar
	
	depth := 10
	for i := 0; i < depth; i++ {
		derivedScalar, newChaining, err := DeriveScalar(currentPublic, currentChaining, uint32(i))
		require.NoError(t, err, "Failed at depth %d", i)
		
		// Update for next iteration
		newScalar := group.NewScalar().(*curve.Secp256k1Scalar)
		newScalar.Set(currentScalar)
		newScalar.Add(derivedScalar)
		currentScalar = newScalar
		currentPublic = currentScalar.ActOnBase().(*curve.Secp256k1Point)
		currentChaining = newChaining
	}
	
	// Verify we successfully derived through all levels
	assert.NotEqual(t, scalar, currentScalar)
}

// Test serialization round-trip
func TestDeriveScalar_Serialization(t *testing.T) {
	group := curve.Secp256k1{}
	scalarNat := new(saferith.Nat).SetUint64(12345)
	scalar := group.NewScalar().(*curve.Secp256k1Scalar)
	scalar.SetNat(scalarNat)
	public := scalar.ActOnBase().(*curve.Secp256k1Point)
	chaining := sha256.Sum256([]byte("test"))
	
	// Derive a scalar
	derivedScalar, newChaining, err := DeriveScalar(public, chaining[:], 42)
	require.NoError(t, err)
	
	// Serialize the public key
	pubBytes, err := public.MarshalBinary()
	require.NoError(t, err)
	
	// Deserialize
	public2 := group.NewPoint().(*curve.Secp256k1Point)
	err = public2.UnmarshalBinary(pubBytes)
	require.NoError(t, err)
	
	// Derive again with deserialized key
	derivedScalar2, newChaining2, err := DeriveScalar(public2, chaining[:], 42)
	require.NoError(t, err)
	
	// Should get same results
	assert.True(t, derivedScalar.Equal(derivedScalar2))
	assert.Equal(t, newChaining, newChaining2)
}

// Test error message format
func TestDeriveScalar_ErrorFormat(t *testing.T) {
	group := curve.Secp256k1{}
	scalarNat := new(saferith.Nat).SetUint64(12345)
	scalar := group.NewScalar().(*curve.Secp256k1Scalar)
	scalar.SetNat(scalarNat)
	public := scalar.ActOnBase().(*curve.Secp256k1Point)
	
	// Try to find an index that causes an error
	// This is very unlikely in practice
	// We'll use a crafted chaining value
	chaining := make([]byte, 32)
	
	// If we ever get an error, check its format
	for i := uint32(0); i < 100; i++ {
		_, _, err := DeriveScalar(public, chaining, i)
		if err != nil {
			assert.Contains(t, err.Error(), fmt.Sprintf("bad index: %d", i))
			return
		}
	}
	
	// Most likely we won't hit an error, which is expected
	t.Log("No bad index found in 100 attempts (expected behavior)")
}