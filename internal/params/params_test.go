package params

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSecurityParameters(t *testing.T) {
	// Test basic security parameters
	assert.Equal(t, 256, SecParam, "SecParam should be 256")
	assert.Equal(t, 32, SecBytes, "SecBytes should be 32")
	assert.Equal(t, 128, OTParam, "OTParam should be 128")
	assert.Equal(t, 16, OTBytes, "OTBytes should be 16")
	assert.Equal(t, 80, StatParam, "StatParam should be 80")
}

func TestZKModIterations(t *testing.T) {
	// Verify ZKModIterations is set to expected value
	assert.Equal(t, 12, ZKModIterations, "ZKModIterations should be 12")
	// Ensure it's less than StatParam as per the comment
	assert.Less(t, ZKModIterations, StatParam, "ZKModIterations should be less than StatParam for efficiency")
}

func TestLengthParameters(t *testing.T) {
	// Test L and related parameters
	assert.Equal(t, 256, L, "L should be 256")
	assert.Equal(t, 1280, LPrime, "LPrime should be 1280")
	assert.Equal(t, 512, Epsilon, "Epsilon should be 512")

	// Test computed values
	assert.Equal(t, 768, LPlusEpsilon, "LPlusEpsilon should be 768")
	assert.Equal(t, L+Epsilon, LPlusEpsilon, "LPlusEpsilon should equal L + Epsilon")

	assert.Equal(t, 1792, LPrimePlusEpsilon, "LPrimePlusEpsilon should be 1792")
	assert.Equal(t, LPrime+Epsilon, LPrimePlusEpsilon, "LPrimePlusEpsilon should equal LPrime + Epsilon")
}

func TestModulusParameters(t *testing.T) {
	// Test modulus-related parameters
	assert.Equal(t, 2048, BitsIntModN, "BitsIntModN should be 2048")
	assert.Equal(t, 256, BytesIntModN, "BytesIntModN should be 256")
	assert.Equal(t, BitsIntModN/8, BytesIntModN, "BytesIntModN should be BitsIntModN/8")
}

func TestPaillierParameters(t *testing.T) {
	// Test Paillier cryptosystem parameters
	assert.Equal(t, 1024, BitsBlumPrime, "BitsBlumPrime should be 1024")
	assert.Equal(t, 2048, BitsPaillier, "BitsPaillier should be 2048")
	assert.Equal(t, 2*BitsBlumPrime, BitsPaillier, "BitsPaillier should be 2*BitsBlumPrime")

	assert.Equal(t, 256, BytesPaillier, "BytesPaillier should be 256")
	assert.Equal(t, BitsPaillier/8, BytesPaillier, "BytesPaillier should be BitsPaillier/8")

	assert.Equal(t, 512, BytesCiphertext, "BytesCiphertext should be 512")
	assert.Equal(t, 2*BytesPaillier, BytesCiphertext, "BytesCiphertext should be 2*BytesPaillier")
}

func TestParameterRelationships(t *testing.T) {
	// Test that parameters have expected relationships

	// Security parameter relationships
	assert.Equal(t, SecParam*1, L, "L should be 1*SecParam")
	assert.Equal(t, SecParam*5, LPrime, "LPrime should be 5*SecParam")
	assert.Equal(t, SecParam*2, Epsilon, "Epsilon should be 2*SecParam")

	// Bit/byte conversions
	assert.Equal(t, SecParam/8, SecBytes, "SecBytes should be SecParam/8")
	assert.Equal(t, OTParam/8, OTBytes, "OTBytes should be OTParam/8")

	// Modulus size relationships
	assert.Equal(t, 8*SecParam, BitsIntModN, "BitsIntModN should be 8*SecParam")
	assert.Equal(t, 4*SecParam, BitsBlumPrime, "BitsBlumPrime should be 4*SecParam")

	// Paillier relationships
	assert.Greater(t, BitsPaillier, BitsBlumPrime, "BitsPaillier should be greater than BitsBlumPrime")
	assert.Greater(t, BytesCiphertext, BytesPaillier, "BytesCiphertext should be greater than BytesPaillier")
}

func TestParameterConsistency(t *testing.T) {
	// Ensure all byte parameters are multiples of 8 bits
	assert.Equal(t, 0, SecParam%8, "SecParam should be divisible by 8")
	assert.Equal(t, 0, OTParam%8, "OTParam should be divisible by 8")
	assert.Equal(t, 0, BitsIntModN%8, "BitsIntModN should be divisible by 8")
	assert.Equal(t, 0, BitsPaillier%8, "BitsPaillier should be divisible by 8")
	assert.Equal(t, 0, BitsBlumPrime%8, "BitsBlumPrime should be divisible by 8")
}

// Benchmark parameter calculations (even though they're constants)
func BenchmarkParameterAccess(b *testing.B) {
	var result int
	for i := 0; i < b.N; i++ {
		result = SecParam + LPrime + Epsilon + BitsIntModN + BitsPaillier
	}
	_ = result
}
