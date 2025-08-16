package elgamal

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/sample"
	"github.com/stretchr/testify/assert"
)

// Test basic encryption and decryption
func TestEncrypt(t *testing.T) {
	group := curve.Secp256k1{}
	
	// Generate a key pair
	privateKey := sample.Scalar(rand.Reader, group)
	publicKey := privateKey.ActOnBase()
	
	// Generate a message
	message := sample.Scalar(rand.Reader, group)
	
	// Encrypt the message
	ciphertext, nonce := Encrypt(publicKey, message)
	
	// Verify ciphertext is valid
	assert.NotNil(t, ciphertext)
	assert.NotNil(t, ciphertext.L)
	assert.NotNil(t, ciphertext.M)
	assert.NotNil(t, nonce)
	
	// Verify L = nonce⋅G
	expectedL := nonce.ActOnBase()
	lBytes, _ := ciphertext.L.MarshalBinary()
	expectedLBytes, _ := expectedL.MarshalBinary()
	assert.Equal(t, expectedLBytes, lBytes, "L should equal nonce⋅G")
	
	// Verify M = message⋅G + nonce⋅public
	messageG := message.ActOnBase()
	noncePub := nonce.Act(publicKey)
	expectedM := messageG.Add(noncePub)
	mBytes, _ := ciphertext.M.MarshalBinary()
	expectedMBytes, _ := expectedM.MarshalBinary()
	assert.Equal(t, expectedMBytes, mBytes, "M should equal message⋅G + nonce⋅public")
	
	// Verify decryption: message⋅G = M - privateKey⋅L
	// privateKey⋅L = privateKey⋅(nonce⋅G) = nonce⋅(privateKey⋅G) = nonce⋅publicKey
	privL := privateKey.Act(ciphertext.L)
	privLNeg := privL.Negate()
	decryptedMessageG := ciphertext.M.Add(privLNeg)
	
	messageGBytes, _ := messageG.MarshalBinary()
	decryptedBytes, _ := decryptedMessageG.MarshalBinary()
	assert.Equal(t, messageGBytes, decryptedBytes, "Decryption should recover message⋅G")
}

// Test Valid method
func TestCiphertext_Valid(t *testing.T) {
	group := curve.Secp256k1{}
	
	// Generate valid ciphertext
	privateKey := sample.Scalar(rand.Reader, group)
	publicKey := privateKey.ActOnBase()
	message := sample.Scalar(rand.Reader, group)
	validCiphertext, _ := Encrypt(publicKey, message)
	
	tests := []struct {
		name       string
		ciphertext *Ciphertext
		expected   bool
	}{
		{
			name:       "valid ciphertext",
			ciphertext: validCiphertext,
			expected:   true,
		},
		{
			name:       "nil ciphertext",
			ciphertext: nil,
			expected:   false,
		},
		{
			name: "nil L",
			ciphertext: &Ciphertext{
				L: nil,
				M: validCiphertext.M,
			},
			expected: false,
		},
		{
			name: "nil M",
			ciphertext: &Ciphertext{
				L: validCiphertext.L,
				M: nil,
			},
			expected: false,
		},
		{
			name: "identity L",
			ciphertext: &Ciphertext{
				L: group.NewPoint(), // identity
				M: validCiphertext.M,
			},
			expected: false,
		},
		{
			name: "identity M",
			ciphertext: &Ciphertext{
				L: validCiphertext.L,
				M: group.NewPoint(), // identity
			},
			expected: false,
		},
	}
	
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.ciphertext.Valid()
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Test Empty function
func TestEmpty(t *testing.T) {
	group := curve.Secp256k1{}
	
	empty := Empty(group)
	
	assert.NotNil(t, empty)
	assert.NotNil(t, empty.L)
	assert.NotNil(t, empty.M)
	assert.True(t, empty.L.IsIdentity())
	assert.True(t, empty.M.IsIdentity())
	assert.False(t, empty.Valid(), "Empty ciphertext should not be valid")
}

// Test WriteTo method
func TestCiphertext_WriteTo(t *testing.T) {
	group := curve.Secp256k1{}
	
	// Generate ciphertext
	privateKey := sample.Scalar(rand.Reader, group)
	publicKey := privateKey.ActOnBase()
	message := sample.Scalar(rand.Reader, group)
	ciphertext, _ := Encrypt(publicKey, message)
	
	// Write to buffer
	var buf bytes.Buffer
	n, err := ciphertext.WriteTo(&buf)
	
	assert.NoError(t, err)
	assert.Greater(t, n, int64(0))
	assert.Greater(t, buf.Len(), 0)
	
	// Verify we can read back the data
	data := buf.Bytes()
	
	// L and M should be marshaled one after another
	lSize := len(data) / 2 // Assuming L and M are same size for secp256k1
	lData := data[:lSize]
	mData := data[lSize:]
	
	// Unmarshal L
	lPoint := group.NewPoint()
	err = lPoint.UnmarshalBinary(lData)
	assert.NoError(t, err)
	
	// Unmarshal M
	mPoint := group.NewPoint()
	err = mPoint.UnmarshalBinary(mData)
	assert.NoError(t, err)
	
	// Verify they match original
	lBytes, _ := ciphertext.L.MarshalBinary()
	mBytes, _ := ciphertext.M.MarshalBinary()
	assert.Equal(t, lBytes, lData)
	assert.Equal(t, mBytes, mData)
}

// Test WriteTo with writer error
func TestCiphertext_WriteTo_Error(t *testing.T) {
	group := curve.Secp256k1{}
	
	// Generate ciphertext
	privateKey := sample.Scalar(rand.Reader, group)
	publicKey := privateKey.ActOnBase()
	message := sample.Scalar(rand.Reader, group)
	ciphertext, _ := Encrypt(publicKey, message)
	
	// Use a writer that fails after some bytes
	failWriter := &failingWriter{failAfter: 10}
	
	n, err := ciphertext.WriteTo(failWriter)
	assert.Error(t, err)
	assert.Equal(t, int64(10), n)
}

// Test Domain method
func TestCiphertext_Domain(t *testing.T) {
	c := Ciphertext{}
	assert.Equal(t, "ElGamal Ciphertext", c.Domain())
}

// Test encryption with different groups
func TestEncrypt_DifferentGroups(t *testing.T) {
	testGroups := []curve.Curve{
		curve.Secp256k1{},
		// Add other curves if available
	}
	
	for _, group := range testGroups {
		t.Run(group.Name(), func(t *testing.T) {
			// Generate key pair
			privateKey := sample.Scalar(rand.Reader, group)
			publicKey := privateKey.ActOnBase()
			
			// Generate message
			message := sample.Scalar(rand.Reader, group)
			
			// Encrypt
			ciphertext, nonce := Encrypt(publicKey, message)
			
			assert.NotNil(t, ciphertext)
			assert.NotNil(t, nonce)
			assert.True(t, ciphertext.Valid())
		})
	}
}

// Test homomorphic property
func TestHomomorphicProperty(t *testing.T) {
	group := curve.Secp256k1{}
	
	// Generate key pair
	privateKey := sample.Scalar(rand.Reader, group)
	publicKey := privateKey.ActOnBase()
	
	// Generate two messages
	message1 := sample.Scalar(rand.Reader, group)
	message2 := sample.Scalar(rand.Reader, group)
	
	// Encrypt both messages
	c1, nonce1 := Encrypt(publicKey, message1)
	c2, nonce2 := Encrypt(publicKey, message2)
	
	// Add ciphertexts: (L1+L2, M1+M2)
	sumL := c1.L.Add(c2.L)
	sumM := c1.M.Add(c2.M)
	sumCiphertext := &Ciphertext{L: sumL, M: sumM}
	
	// The sum should decrypt to (message1 + message2)⋅G
	// Decrypt: message⋅G = M - privateKey⋅L
	privSumL := privateKey.Act(sumCiphertext.L)
	privSumLNeg := privSumL.Negate()
	decryptedSumG := sumCiphertext.M.Add(privSumLNeg)
	
	// Expected: (message1 + message2)⋅G
	sumMessage := group.NewScalar().Set(message1).Add(message2)
	expectedSumG := sumMessage.ActOnBase()
	
	// Compare
	decryptedBytes, _ := decryptedSumG.MarshalBinary()
	expectedBytes, _ := expectedSumG.MarshalBinary()
	assert.Equal(t, expectedBytes, decryptedBytes, "Homomorphic addition should work")
	
	// Also verify the nonces add up correctly
	// L1 + L2 = nonce1⋅G + nonce2⋅G = (nonce1 + nonce2)⋅G
	sumNonce := group.NewScalar().Set(nonce1).Add(nonce2)
	expectedL := sumNonce.ActOnBase()
	sumLBytes, _ := sumL.MarshalBinary()
	expectedLBytes, _ := expectedL.MarshalBinary()
	assert.Equal(t, expectedLBytes, sumLBytes, "L components should add correctly")
}

// Test multiple encryptions of same message
func TestMultipleEncryptions(t *testing.T) {
	group := curve.Secp256k1{}
	
	// Generate key pair
	privateKey := sample.Scalar(rand.Reader, group)
	publicKey := privateKey.ActOnBase()
	
	// Generate message
	message := sample.Scalar(rand.Reader, group)
	
	// Encrypt multiple times
	c1, nonce1 := Encrypt(publicKey, message)
	c2, nonce2 := Encrypt(publicKey, message)
	
	// Ciphertexts should be different (due to random nonce)
	c1LBytes, _ := c1.L.MarshalBinary()
	c2LBytes, _ := c2.L.MarshalBinary()
	assert.NotEqual(t, c1LBytes, c2LBytes, "Different encryptions should use different nonces")
	
	// But they should decrypt to the same message
	// Decrypt c1
	priv1L := privateKey.Act(c1.L)
	priv1LNeg := priv1L.Negate()
	decrypted1 := c1.M.Add(priv1LNeg)
	
	// Decrypt c2
	priv2L := privateKey.Act(c2.L)
	priv2LNeg := priv2L.Negate()
	decrypted2 := c2.M.Add(priv2LNeg)
	
	// Should be equal
	dec1Bytes, _ := decrypted1.MarshalBinary()
	dec2Bytes, _ := decrypted2.MarshalBinary()
	assert.Equal(t, dec1Bytes, dec2Bytes, "Different encryptions of same message should decrypt to same value")
	
	// Nonces should be different
	assert.False(t, nonce1.Equal(nonce2), "Nonces should be different")
}

// Test encryption with zero message
func TestEncrypt_ZeroMessage(t *testing.T) {
	group := curve.Secp256k1{}
	
	// Generate key pair
	privateKey := sample.Scalar(rand.Reader, group)
	publicKey := privateKey.ActOnBase()
	
	// Zero message
	zeroMessage := group.NewScalar()
	
	// Encrypt
	ciphertext, nonce := Encrypt(publicKey, zeroMessage)
	
	assert.NotNil(t, ciphertext)
	assert.True(t, ciphertext.Valid())
	
	// M should equal nonce⋅publicKey (since message⋅G = 0)
	expectedM := nonce.Act(publicKey)
	mBytes, _ := ciphertext.M.MarshalBinary()
	expectedMBytes, _ := expectedM.MarshalBinary()
	assert.Equal(t, expectedMBytes, mBytes, "Zero message encryption should work")
}

// Test encryption with identity public key
func TestEncrypt_IdentityPublicKey(t *testing.T) {
	group := curve.Secp256k1{}
	
	// Identity public key (point at infinity)
	identityKey := group.NewPoint()
	
	// Generate message
	message := sample.Scalar(rand.Reader, group)
	
	// Encrypt
	ciphertext, nonce := Encrypt(identityKey, message)
	
	assert.NotNil(t, ciphertext)
	// The ciphertext should still be valid structurally
	assert.NotNil(t, ciphertext.L)
	assert.NotNil(t, ciphertext.M)
	
	// M should equal message⋅G (since nonce⋅identity = identity)
	expectedM := message.ActOnBase()
	mBytes, _ := ciphertext.M.MarshalBinary()
	expectedMBytes, _ := expectedM.MarshalBinary()
	assert.Equal(t, expectedMBytes, mBytes, "Encryption with identity key should work")
	
	// L should still be nonce⋅G
	expectedL := nonce.ActOnBase()
	lBytes, _ := ciphertext.L.MarshalBinary()
	expectedLBytes, _ := expectedL.MarshalBinary()
	assert.Equal(t, expectedLBytes, lBytes)
}

// Benchmark encryption
func BenchmarkEncrypt(b *testing.B) {
	group := curve.Secp256k1{}
	
	// Generate key pair
	privateKey := sample.Scalar(rand.Reader, group)
	publicKey := privateKey.ActOnBase()
	
	// Generate message
	message := sample.Scalar(rand.Reader, group)
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_, _ = Encrypt(publicKey, message)
	}
}

// Benchmark WriteTo
func BenchmarkCiphertext_WriteTo(b *testing.B) {
	group := curve.Secp256k1{}
	
	// Generate ciphertext
	privateKey := sample.Scalar(rand.Reader, group)
	publicKey := privateKey.ActOnBase()
	message := sample.Scalar(rand.Reader, group)
	ciphertext, _ := Encrypt(publicKey, message)
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		_, _ = ciphertext.WriteTo(&buf)
	}
}

// Helper type for testing WriteTo errors
type failingWriter struct {
	written   int
	failAfter int
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.written+len(p) > w.failAfter {
		n := w.failAfter - w.written
		w.written = w.failAfter
		if n < 0 {
			n = 0
		}
		return n, io.ErrShortWrite
	}
	w.written += len(p)
	return len(p), nil
}

// Test re-encryption (transform encryption under one key to another)
func TestReEncryption(t *testing.T) {
	group := curve.Secp256k1{}
	
	// Generate two key pairs
	privateKey1 := sample.Scalar(rand.Reader, group)
	publicKey1 := privateKey1.ActOnBase()
	
	privateKey2 := sample.Scalar(rand.Reader, group)
	publicKey2 := privateKey2.ActOnBase()
	
	// Generate message
	message := sample.Scalar(rand.Reader, group)
	
	// Encrypt under first key
	c1, _ := Encrypt(publicKey1, message)
	
	// To re-encrypt from key1 to key2, we need the re-encryption key
	// In proxy re-encryption: reKey = privateKey2 / privateKey1
	// But ElGamal doesn't directly support this without additional infrastructure
	
	// This test just verifies independent encryptions
	c2, _ := Encrypt(publicKey2, message)
	
	assert.True(t, c1.Valid())
	assert.True(t, c2.Valid())
	
	// The ciphertexts should be different
	c1LBytes, _ := c1.L.MarshalBinary()
	c2LBytes, _ := c2.L.MarshalBinary()
	assert.NotEqual(t, c1LBytes, c2LBytes)
}

// Fuzz test for encryption
func FuzzEncrypt(f *testing.F) {
	group := curve.Secp256k1{}
	
	// Add seed values
	f.Add([]byte{1, 2, 3}, []byte{4, 5, 6})
	f.Add([]byte{255}, []byte{128})
	
	f.Fuzz(func(t *testing.T, privKeyBytes, messageBytes []byte) {
		if len(privKeyBytes) == 0 || len(messageBytes) == 0 {
			t.Skip()
		}
		
		// Create scalar from bytes
		privScalar := group.NewScalar()
		privNat := new(saferith.Nat).SetBytes(privKeyBytes)
		if privNat.Eq(new(saferith.Nat)) == 1 {
			t.Skip() // Skip zero private key
		}
		privScalar.(*curve.Secp256k1Scalar).SetNat(privNat)
		
		publicKey := privScalar.ActOnBase()
		
		msgScalar := group.NewScalar()
		msgNat := new(saferith.Nat).SetBytes(messageBytes)
		msgScalar.(*curve.Secp256k1Scalar).SetNat(msgNat)
		
		// Should not panic
		ciphertext, nonce := Encrypt(publicKey, msgScalar)
		
		// Basic validation
		assert.NotNil(t, ciphertext)
		assert.NotNil(t, nonce)
		assert.True(t, ciphertext.Valid())
		
		// Verify decryption works
		privL := privScalar.Act(ciphertext.L)
		privLNeg := privL.Negate()
		decrypted := ciphertext.M.Add(privLNeg)
		
		expected := msgScalar.ActOnBase()
		decBytes, _ := decrypted.MarshalBinary()
		expBytes, _ := expected.MarshalBinary()
		assert.Equal(t, expBytes, decBytes)
	})
}

// Test error handling in WriteTo
func TestCiphertext_WriteTo_MarshalError(t *testing.T) {
	// WriteTo assumes Valid() is true, so we skip testing nil cases
	// as they would cause panic (by design - caller should check Valid() first)
	t.Skip("WriteTo assumes Valid() ciphertext - nil cases tested in Valid()")
}