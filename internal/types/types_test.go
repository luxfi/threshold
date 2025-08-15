package types

import (
	"bytes"
	"crypto/rand"
	"io"
	"strings"
	"testing"

	"github.com/luxfi/threshold/internal/params"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmptyRID(t *testing.T) {
	rid := EmptyRID()

	assert.Equal(t, params.SecBytes, len(rid))

	// Should be all zeros
	for _, b := range rid {
		assert.Equal(t, byte(0), b)
	}
}

func TestNewRID(t *testing.T) {
	// Test with crypto/rand reader
	rid, err := NewRID(rand.Reader)
	require.NoError(t, err)
	assert.Equal(t, params.SecBytes, len(rid))

	// Check it's not all zeros (extremely unlikely with crypto/rand)
	allZero := true
	for _, b := range rid {
		if b != 0 {
			allZero = false
			break
		}
	}
	assert.False(t, allZero)
}

func TestNewRID_ReaderError(t *testing.T) {
	// Test with insufficient data
	shortReader := strings.NewReader("short")
	_, err := NewRID(shortReader)
	assert.Error(t, err)
}

func TestRID_XOR(t *testing.T) {
	// Create two test RIDs
	rid1 := EmptyRID()
	rid2 := EmptyRID()

	// Set some test values
	rid1[0] = 0xAA
	rid1[1] = 0xBB
	rid2[0] = 0xFF
	rid2[1] = 0x00

	// Create copies for comparison
	originalRid1 := rid1.Copy()

	// Perform XOR
	rid1.XOR(rid2)

	// Check results
	assert.Equal(t, byte(0x55), rid1[0]) // 0xAA ^ 0xFF = 0x55
	assert.Equal(t, byte(0xBB), rid1[1]) // 0xBB ^ 0x00 = 0xBB

	// Check that rid2 is unchanged
	assert.Equal(t, byte(0xFF), rid2[0])
	assert.Equal(t, byte(0x00), rid2[1])

	// Test XOR is reversible
	rid1.XOR(rid2)
	assert.Equal(t, originalRid1, rid1)
}

func TestRID_XOR_DifferentLengths(t *testing.T) {
	rid1 := make(RID, params.SecBytes)
	rid2 := make(RID, params.SecBytes-1) // Different length

	rid1[0] = 0xAA
	originalValue := rid1[0]

	// XOR with different length should not modify rid1
	rid1.XOR(rid2)
	assert.Equal(t, originalValue, rid1[0])
}

func TestRID_WriteTo(t *testing.T) {
	rid := EmptyRID()
	rid[0] = 0xAA
	rid[1] = 0xBB

	var buf bytes.Buffer
	n, err := rid.WriteTo(&buf)

	assert.NoError(t, err)
	assert.Equal(t, int64(params.SecBytes), n)
	assert.Equal(t, params.SecBytes, buf.Len())
	assert.Equal(t, byte(0xAA), buf.Bytes()[0])
	assert.Equal(t, byte(0xBB), buf.Bytes()[1])
}

func TestRID_WriteTo_Nil(t *testing.T) {
	var rid RID // nil RID

	var buf bytes.Buffer
	n, err := rid.WriteTo(&buf)

	assert.Error(t, err)
	assert.Equal(t, io.ErrUnexpectedEOF, err)
	assert.Equal(t, int64(0), n)
}

func TestRID_Domain(t *testing.T) {
	rid := EmptyRID()
	domain := rid.Domain()
	assert.Equal(t, "RID", domain)
}

func TestRID_Validate(t *testing.T) {
	// Valid RID with correct length and non-zero content
	rid := EmptyRID()
	rid[0] = 0x01
	err := rid.Validate()
	assert.NoError(t, err)

	// Invalid RID: all zeros
	zeroRID := EmptyRID()
	err = zeroRID.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rid is 0")

	// Invalid RID: wrong length
	wrongLengthRID := make(RID, params.SecBytes-1)
	err = wrongLengthRID.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "incorrect length")
}

func TestRID_Copy(t *testing.T) {
	original := EmptyRID()
	original[0] = 0xAA
	original[1] = 0xBB

	copied := original.Copy()

	// Should be equal
	assert.Equal(t, original, copied)

	// Should be independent
	copied[0] = 0xFF
	assert.NotEqual(t, original[0], copied[0])
	assert.Equal(t, byte(0xAA), original[0])
	assert.Equal(t, byte(0xFF), copied[0])
}

func TestThresholdWrapper_WriteTo(t *testing.T) {
	threshold := ThresholdWrapper(42)

	var buf bytes.Buffer
	n, err := threshold.WriteTo(&buf)

	assert.NoError(t, err)
	assert.Equal(t, int64(4), n)
	assert.Equal(t, 4, buf.Len())

	// Check the written bytes (big endian)
	bytes := buf.Bytes()
	assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x2A}, bytes)
}

func TestThresholdWrapper_WriteTo_MaxValue(t *testing.T) {
	threshold := ThresholdWrapper(0xFFFFFFFF)

	var buf bytes.Buffer
	n, err := threshold.WriteTo(&buf)

	assert.NoError(t, err)
	assert.Equal(t, int64(4), n)
	assert.Equal(t, []byte{0xFF, 0xFF, 0xFF, 0xFF}, buf.Bytes())
}

func TestThresholdWrapper_Domain(t *testing.T) {
	threshold := ThresholdWrapper(10)
	domain := threshold.Domain()
	assert.Equal(t, "Threshold", domain)
}

func TestRID_XOR_SelfXOR(t *testing.T) {
	rid := EmptyRID()
	rid[0] = 0xAA
	rid[1] = 0xBB

	original := rid.Copy()

	// XOR with itself should result in all zeros
	rid.XOR(original)

	for _, b := range rid {
		assert.Equal(t, byte(0), b)
	}
}

func TestRID_XOR_Commutativity(t *testing.T) {
	rid1 := EmptyRID()
	rid2 := EmptyRID()

	rid1[0] = 0xAA
	rid2[0] = 0xFF

	// Test a XOR b = b XOR a
	result1 := rid1.Copy()
	result1.XOR(rid2)

	result2 := rid2.Copy()
	result2.XOR(rid1)

	assert.Equal(t, result1, result2)
}
