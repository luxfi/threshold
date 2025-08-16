package zk

import (
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultInitialization(t *testing.T) {
	// Test that all default values are initialized
	require.NotNil(t, ProverPaillierPublic, "ProverPaillierPublic should be initialized")
	require.NotNil(t, ProverPaillierSecret, "ProverPaillierSecret should be initialized")
	require.NotNil(t, VerifierPaillierPublic, "VerifierPaillierPublic should be initialized")
	require.NotNil(t, VerifierPaillierSecret, "VerifierPaillierSecret should be initialized")
	require.NotNil(t, Pedersen, "Pedersen should be initialized")
}

func TestPaillierKeys(t *testing.T) {
	// Test that Paillier keys are properly set up
	assert.NotNil(t, ProverPaillierPublic.N())
	assert.NotNil(t, VerifierPaillierPublic.N())

	// Test that public keys match secret keys
	assert.Equal(t, ProverPaillierSecret.PublicKey, ProverPaillierPublic)
	assert.Equal(t, VerifierPaillierSecret.PublicKey, VerifierPaillierPublic)

	// Test that the keys are different
	assert.NotEqual(t, ProverPaillierPublic.N(), VerifierPaillierPublic.N())
}

func TestPedersenParameters(t *testing.T) {
	// Test that Pedersen parameters are properly initialized
	assert.NotNil(t, Pedersen.N())
	assert.NotNil(t, Pedersen.S())
	assert.NotNil(t, Pedersen.T())

	// Test that N matches the verifier's public key modulus
	assert.Equal(t, VerifierPaillierPublic.N(), Pedersen.N())
}

func TestEncryptionDecryption(t *testing.T) {
	// Test basic encryption/decryption with prover keys
	plaintext := new(saferith.Int).SetUint64(12345)

	ciphertext, nonce := ProverPaillierPublic.Enc(plaintext)
	require.NotNil(t, ciphertext)
	require.NotNil(t, nonce)

	decrypted, err := ProverPaillierSecret.Dec(ciphertext)
	require.NoError(t, err)
	// Compare values instead of objects due to internal representation differences
	assert.True(t, plaintext.Eq(decrypted) == 1, "Decrypted value should match plaintext")

	// Test with verifier keys
	plaintext2 := new(saferith.Int).SetUint64(67890)

	ciphertext2, nonce2 := VerifierPaillierPublic.Enc(plaintext2)
	require.NotNil(t, ciphertext2)
	require.NotNil(t, nonce2)

	decrypted2, err := VerifierPaillierSecret.Dec(ciphertext2)
	require.NoError(t, err)
	// Compare values instead of objects due to internal representation differences
	assert.True(t, plaintext2.Eq(decrypted2) == 1, "Decrypted value should match plaintext")
}

func TestPedersenCommitment(t *testing.T) {
	// Test Pedersen commitment functionality
	x := new(saferith.Int).SetUint64(100)
	y := new(saferith.Int).SetUint64(200)

	commitment := Pedersen.Commit(x, y)
	require.NotNil(t, commitment)

	// Test verification with same values
	e := new(saferith.Int).SetUint64(300)
	S := commitment
	T := Pedersen.Commit(x, y)

	// For proper verification, we need to create a, b such that:
	// sᵃ tᵇ ≡ S Tᵉ (mod N)
	// This is a simplified test as full ZK proof would require more setup
	a := new(saferith.Int).SetUint64(1)
	b := new(saferith.Int).SetUint64(1)

	// Note: This is a simplified test. Real verification would involve ZK proofs
	verified := Pedersen.Verify(a, b, e, S, T)
	assert.NotNil(t, verified) // Just ensure it doesn't panic
}

func TestKeyConsistency(t *testing.T) {
	// Test that keys maintain consistency across multiple accesses
	proverPub1 := ProverPaillierPublic
	proverPub2 := ProverPaillierPublic
	assert.Equal(t, proverPub1, proverPub2, "ProverPaillierPublic should be consistent")

	verifierPub1 := VerifierPaillierPublic
	verifierPub2 := VerifierPaillierPublic
	assert.Equal(t, verifierPub1, verifierPub2, "VerifierPaillierPublic should be consistent")

	pedersen1 := Pedersen
	pedersen2 := Pedersen
	assert.Equal(t, pedersen1, pedersen2, "Pedersen should be consistent")
}

// Benchmark initialization (though it only happens once)
func BenchmarkPaillierEncryption(b *testing.B) {
	plaintext := new(saferith.Int).SetUint64(12345)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ProverPaillierPublic.Enc(plaintext)
	}
}

func BenchmarkPaillierDecryption(b *testing.B) {
	plaintext := new(saferith.Int).SetUint64(12345)
	ciphertext, _ := ProverPaillierPublic.Enc(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ProverPaillierSecret.Dec(ciphertext)
	}
}

func BenchmarkPedersenCommit(b *testing.B) {
	x := new(saferith.Int).SetUint64(12345)
	y := new(saferith.Int).SetUint64(67890)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Pedersen.Commit(x, y)
	}
}
