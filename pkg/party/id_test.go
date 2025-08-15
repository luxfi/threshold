package party

import (
	"bytes"
	"io"
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestID_Scalar(t *testing.T) {
	tests := []struct {
		name  string
		id    ID
		group curve.Curve
	}{
		{
			name:  "simple_id",
			id:    ID("test"),
			group: curve.Secp256k1{},
		},
		{
			name:  "longer_id",
			id:    ID("this_is_a_longer_test_party_id"),
			group: curve.Secp256k1{},
		},
		{
			name:  "empty_id",
			id:    ID(""),
			group: curve.Secp256k1{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scalar := tt.id.Scalar(tt.group)
			assert.NotNil(t, scalar)

			// Test that the scalar is deterministic
			scalar2 := tt.id.Scalar(tt.group)
			assert.True(t, scalar.Equal(scalar2))
		})
	}
}

func TestID_WriteTo(t *testing.T) {
	tests := []struct {
		name        string
		id          ID
		expectError bool
	}{
		{
			name:        "valid_id",
			id:          ID("party1"),
			expectError: false,
		},
		{
			name:        "empty_id",
			id:          ID(""),
			expectError: true,
		},
		{
			name:        "long_id",
			id:          ID("very_long_party_identifier_name"),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			n, err := tt.id.WriteTo(&buf)

			if tt.expectError {
				assert.Error(t, err)
				assert.Equal(t, io.ErrUnexpectedEOF, err)
				assert.Equal(t, int64(0), n)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, int64(len(tt.id)), n)
				assert.Equal(t, string(tt.id), buf.String())
			}
		})
	}
}

func TestID_Domain(t *testing.T) {
	id := ID("test")
	domain := id.Domain()
	assert.Equal(t, "ID", domain)
}

func TestNewPointMap(t *testing.T) {
	group := curve.Secp256k1{}

	// Create some test points
	points := make(map[ID]curve.Point)
	points[ID("party1")] = group.NewBasePoint()
	points[ID("party2")] = group.NewBasePoint()

	pointMap := NewPointMap(points)

	assert.NotNil(t, pointMap)
	assert.Equal(t, group, pointMap.group)
	assert.Equal(t, points, pointMap.Points)
}

func TestEmptyPointMap(t *testing.T) {
	group := curve.Secp256k1{}
	pointMap := EmptyPointMap(group)

	assert.NotNil(t, pointMap)
	assert.Equal(t, group, pointMap.group)
	assert.Nil(t, pointMap.Points)
}

func TestPointMap_MarshalUnmarshal(t *testing.T) {
	group := curve.Secp256k1{}

	// Create test points
	points := make(map[ID]curve.Point)
	points[ID("party1")] = group.NewBasePoint()
	points[ID("party2")] = group.NewBasePoint()

	original := NewPointMap(points)

	// Marshal
	data, err := original.MarshalBinary()
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Unmarshal
	unmarshaled := EmptyPointMap(group)
	err = unmarshaled.UnmarshalBinary(data)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, len(original.Points), len(unmarshaled.Points))
	for id, originalPoint := range original.Points {
		unmarshaledPoint, exists := unmarshaled.Points[id]
		assert.True(t, exists)
		assert.True(t, originalPoint.Equal(unmarshaledPoint))
	}
}

func TestPointMap_UnmarshalBinary_NoGroup(t *testing.T) {
	pointMap := &PointMap{}
	err := pointMap.UnmarshalBinary([]byte("test"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "without setting a group")
}

func TestPointMap_UnmarshalBinary_InvalidData(t *testing.T) {
	group := curve.Secp256k1{}
	pointMap := EmptyPointMap(group)

	err := pointMap.UnmarshalBinary([]byte("invalid cbor data"))
	assert.Error(t, err)
}

func TestPointMap_MarshalBinary_EmptyMap(t *testing.T) {
	group := curve.Secp256k1{}
	pointMap := EmptyPointMap(group)
	pointMap.Points = make(map[ID]curve.Point)

	data, err := pointMap.MarshalBinary()
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	// Unmarshal back
	unmarshaled := EmptyPointMap(group)
	err = unmarshaled.UnmarshalBinary(data)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(unmarshaled.Points))
}

func TestNewIDSlice(t *testing.T) {
	ids := []ID{"c", "a", "b"}
	slice := NewIDSlice(ids)

	// Should be sorted
	assert.True(t, slice.Valid())
	assert.Equal(t, IDSlice{"a", "b", "c"}, slice)

	// Original slice should not be modified
	assert.Equal(t, []ID{"c", "a", "b"}, ids)
}

func TestIDSlice_Contains(t *testing.T) {
	slice := NewIDSlice([]ID{"a", "b", "c", "d"})

	assert.True(t, slice.Contains("a"))
	assert.True(t, slice.Contains("b", "c"))
	assert.True(t, slice.Contains("a", "b", "c", "d"))
	assert.False(t, slice.Contains("e"))
	assert.False(t, slice.Contains("a", "e"))
}

func TestIDSlice_Valid(t *testing.T) {
	tests := []struct {
		name  string
		slice IDSlice
		valid bool
	}{
		{
			name:  "valid_sorted",
			slice: IDSlice{"a", "b", "c"},
			valid: true,
		},
		{
			name:  "invalid_unsorted",
			slice: IDSlice{"c", "a", "b"},
			valid: false,
		},
		{
			name:  "invalid_duplicates",
			slice: IDSlice{"a", "b", "b"},
			valid: false,
		},
		{
			name:  "empty_slice",
			slice: IDSlice{},
			valid: true,
		},
		{
			name:  "single_element",
			slice: IDSlice{"a"},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, tt.slice.Valid())
		})
	}
}

func TestIDSlice_Copy(t *testing.T) {
	original := IDSlice{"a", "b", "c"}
	copied := original.Copy()

	// Should be equal but different slice
	assert.Equal(t, original, copied)

	// Modifying copy should not affect original
	copied[0] = "z"
	assert.NotEqual(t, original, copied)
	assert.Equal(t, ID("a"), original[0])
}

func TestIDSlice_Remove(t *testing.T) {
	slice := IDSlice{"a", "b", "c", "d"}

	// Remove existing element
	result := slice.Remove("b")
	assert.Equal(t, IDSlice{"a", "c", "d"}, result)

	// Remove non-existing element
	result = slice.Remove("e")
	assert.Equal(t, IDSlice{"a", "b", "c", "d"}, result)

	// Original slice should not be modified
	assert.Equal(t, IDSlice{"a", "b", "c", "d"}, slice)
}

func TestIDSlice_SortInterface(t *testing.T) {
	slice := IDSlice{"c", "a", "b"}

	// Test Len
	assert.Equal(t, 3, slice.Len())

	// Test Less
	assert.True(t, slice.Less(1, 0))  // "a" < "c"
	assert.False(t, slice.Less(0, 1)) // "c" > "a"

	// Test Swap
	slice.Swap(0, 1)
	assert.Equal(t, IDSlice{"a", "c", "b"}, slice)
}

func TestIDSlice_search(t *testing.T) {
	slice := NewIDSlice([]ID{"a", "c", "e", "g"})

	// Find existing elements
	idx, found := slice.search("a")
	assert.True(t, found)
	assert.Equal(t, 0, idx)

	idx, found = slice.search("e")
	assert.True(t, found)
	assert.Equal(t, 2, idx)

	// Search for non-existing elements
	_, found = slice.search("b")
	assert.False(t, found)

	_, found = slice.search("z")
	assert.False(t, found)
}

func TestIDSlice_WriteTo(t *testing.T) {
	tests := []struct {
		name        string
		slice       IDSlice
		expectError bool
	}{
		{
			name:        "valid_slice",
			slice:       IDSlice{"a", "b", "c"},
			expectError: false,
		},
		{
			name:        "nil_slice",
			slice:       nil,
			expectError: true,
		},
		{
			name:        "empty_slice",
			slice:       IDSlice{},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			n, err := tt.slice.WriteTo(&buf)

			if tt.expectError {
				assert.Error(t, err)
				assert.Equal(t, io.ErrUnexpectedEOF, err)
				assert.Equal(t, int64(0), n)
			} else {
				assert.NoError(t, err)
				assert.Greater(t, n, int64(0))
			}
		})
	}
}

func TestIDSlice_Domain(t *testing.T) {
	slice := IDSlice{"a", "b"}
	domain := slice.Domain()
	assert.Equal(t, "IDSlice", domain)
}

func TestIDSlice_String(t *testing.T) {
	tests := []struct {
		slice    IDSlice
		expected string
	}{
		{
			slice:    IDSlice{"a", "b", "c"},
			expected: "a, b, c",
		},
		{
			slice:    IDSlice{},
			expected: "",
		},
		{
			slice:    IDSlice{"single"},
			expected: "single",
		},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, tt.slice.String())
	}
}
