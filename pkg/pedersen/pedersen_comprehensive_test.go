package pedersen

import (
	"bytes"
	"io"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/luxfi/threshold/pkg/math/arith"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test New function
func TestNew(t *testing.T) {
	// Use the benchmark parameters
	params := New(benchParams.n, benchParams.s, benchParams.t)
	require.NotNil(t, params)

	assert.Equal(t, benchN, params.N())
	assert.Equal(t, benchParams.n, params.NArith())
	assert.Equal(t, benchParams.s, params.S())
	assert.Equal(t, benchParams.t, params.T())
}

// Test ValidateParameters
func TestValidateParameters(t *testing.T) {
	// Valid parameters from benchmark
	n := benchN
	s := benchParams.s
	tt := benchParams.t

	tests := []struct {
		name    string
		n       *saferith.Modulus
		s       *saferith.Nat
		t       *saferith.Nat
		wantErr error
	}{
		{
			name:    "valid parameters",
			n:       n,
			s:       s,
			t:       tt,
			wantErr: nil,
		},
		{
			name:    "nil n",
			n:       nil,
			s:       s,
			t:       tt,
			wantErr: ErrNilFields,
		},
		{
			name:    "nil s",
			n:       n,
			s:       nil,
			t:       tt,
			wantErr: ErrNilFields,
		},
		{
			name:    "nil t",
			n:       n,
			s:       s,
			t:       nil,
			wantErr: ErrNilFields,
		},
		{
			name:    "s equals t",
			n:       n,
			s:       s,
			t:       s,
			wantErr: ErrSEqualT,
		},
		{
			name:    "s is zero",
			n:       n,
			s:       new(saferith.Nat).SetUint64(0),
			t:       tt,
			wantErr: ErrNotValidModN,
		},
		{
			name:    "t is zero",
			n:       n,
			s:       s,
			t:       new(saferith.Nat).SetUint64(0),
			wantErr: ErrNotValidModN,
		},
		{
			name:    "s equals n",
			n:       n,
			s:       n.Nat(),
			t:       tt,
			wantErr: ErrNotValidModN,
		},
		{
			name:    "t equals n",
			n:       n,
			s:       s,
			t:       n.Nat(),
			wantErr: ErrNotValidModN,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateParameters(tc.n, tc.s, tc.t)
			if tc.wantErr != nil {
				assert.Equal(t, tc.wantErr, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Test Commit function
func TestCommit(t *testing.T) {
	params := benchParams

	// Test with various x and y values
	testCases := []struct {
		name string
		x    *saferith.Int
		y    *saferith.Int
	}{
		{
			name: "zero values",
			x:    new(saferith.Int).SetUint64(0),
			y:    new(saferith.Int).SetUint64(0),
		},
		{
			name: "small positive values",
			x:    new(saferith.Int).SetUint64(5),
			y:    new(saferith.Int).SetUint64(7),
		},
		{
			name: "large positive values",
			x:    new(saferith.Int).SetUint64(12345),
			y:    new(saferith.Int).SetUint64(67890),
		},
		{
			name: "negative x",
			x:    new(saferith.Int).SetUint64(5).Neg(1),
			y:    new(saferith.Int).SetUint64(7),
		},
		{
			name: "negative y",
			x:    new(saferith.Int).SetUint64(5),
			y:    new(saferith.Int).SetUint64(7).Neg(1),
		},
		{
			name: "both negative",
			x:    new(saferith.Int).SetUint64(5).Neg(1),
			y:    new(saferith.Int).SetUint64(7).Neg(1),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			commitment := params.Commit(tc.x, tc.y)
			require.NotNil(t, commitment)

			// Verify the commitment is in the valid range
			assert.True(t, arith.IsValidNatModN(benchN, commitment))

			// Verify commitment is deterministic
			commitment2 := params.Commit(tc.x, tc.y)
			assert.Equal(t, commitment, commitment2)
		})
	}
}

// Test Verify function
func TestVerify(t *testing.T) {
	params := benchParams

	// Generate a commitment
	x := new(saferith.Int).SetUint64(42)
	y := new(saferith.Int).SetUint64(17)

	S := params.Commit(x, y)

	// Generate e for the verification
	e := new(saferith.Int).SetUint64(0)

	// For e=0, we need s^a * t^b = S * T^0 = S
	// So a=x, b=y, T can be anything
	T := new(saferith.Nat).SetUint64(1)

	tests := []struct {
		name   string
		a      *saferith.Int
		b      *saferith.Int
		e      *saferith.Int
		S      *saferith.Nat
		T      *saferith.Nat
		expect bool
	}{
		{
			name:   "valid verification with e=0",
			a:      x,
			b:      y,
			e:      e,
			S:      S,
			T:      T,
			expect: true,
		},
		{
			name:   "nil a",
			a:      nil,
			b:      y,
			e:      e,
			S:      S,
			T:      T,
			expect: false,
		},
		{
			name:   "nil b",
			a:      x,
			b:      nil,
			e:      e,
			S:      S,
			T:      T,
			expect: false,
		},
		{
			name:   "nil e",
			a:      x,
			b:      y,
			e:      nil,
			S:      S,
			T:      T,
			expect: false,
		},
		{
			name:   "nil S",
			a:      x,
			b:      y,
			e:      e,
			S:      nil,
			T:      T,
			expect: false,
		},
		{
			name:   "nil T",
			a:      x,
			b:      y,
			e:      e,
			S:      S,
			T:      nil,
			expect: false,
		},
		{
			name:   "invalid S (zero)",
			a:      x,
			b:      y,
			e:      e,
			S:      new(saferith.Nat).SetUint64(0),
			T:      T,
			expect: false,
		},
		{
			name:   "invalid S (out of range)",
			a:      x,
			b:      y,
			e:      e,
			S:      benchN.Nat(),
			T:      T,
			expect: false,
		},
		{
			name:   "invalid T (zero)",
			a:      x,
			b:      y,
			e:      e,
			S:      S,
			T:      new(saferith.Nat).SetUint64(0),
			expect: false,
		},
		{
			name:   "invalid T (out of range)",
			a:      x,
			b:      y,
			e:      e,
			S:      S,
			T:      benchN.Nat(),
			expect: false,
		},
		{
			name:   "wrong values",
			a:      new(saferith.Int).SetUint64(1),
			b:      new(saferith.Int).SetUint64(1),
			e:      e,
			S:      S,
			T:      T,
			expect: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := params.Verify(tc.a, tc.b, tc.e, tc.S, tc.T)
			assert.Equal(t, tc.expect, result)
		})
	}
}

// Test commitment properties
func TestCommitmentProperties(t *testing.T) {
	params := benchParams

	// Test homomorphic property: Commit(x1+x2, y1+y2) = Commit(x1,y1) * Commit(x2,y2)
	x1 := new(saferith.Int).SetUint64(10)
	y1 := new(saferith.Int).SetUint64(20)
	x2 := new(saferith.Int).SetUint64(30)
	y2 := new(saferith.Int).SetUint64(40)

	// Compute individual commitments
	c1 := params.Commit(x1, y1)
	c2 := params.Commit(x2, y2)

	// Compute combined commitment
	x3 := new(saferith.Int).Add(x1, x2, -1)
	y3 := new(saferith.Int).Add(y1, y2, -1)
	c3 := params.Commit(x3, y3)

	// Compute product of individual commitments
	c12 := new(saferith.Nat).ModMul(c1, c2, benchN)

	// They should be equal
	assert.Equal(t, c3, c12, "Homomorphic property failed")
}

// Test WriteTo implementation
func TestWriteTo(t *testing.T) {
	params := benchParams

	// Write to buffer
	var buf bytes.Buffer
	n64, err := params.WriteTo(&buf)
	require.NoError(t, err)

	// Check that we wrote something (3 values: N, S, T)
	// Each value is the size of the modulus in bytes
	assert.Greater(t, n64, int64(0))
	assert.Greater(t, buf.Len(), 0)

	// Test nil parameters
	var nilParams *Parameters
	buf.Reset()
	_, err = nilParams.WriteTo(&buf)
	assert.Equal(t, io.ErrUnexpectedEOF, err)
}

// Test Domain implementation
func TestDomain(t *testing.T) {
	params := benchParams

	domain := params.Domain()
	assert.Equal(t, "Pedersen Parameters", domain)

	// Test with a new instance
	newParams := New(benchParams.n, benchParams.s, benchParams.t)
	assert.Equal(t, "Pedersen Parameters", newParams.Domain())
}

// Test Error implementation
func TestError(t *testing.T) {
	tests := []struct {
		err      Error
		expected string
	}{
		{
			err:      ErrNilFields,
			expected: "pedersen: contains nil field",
		},
		{
			err:      ErrSEqualT,
			expected: "pedersen: S cannot be equal to T",
		},
		{
			err:      ErrNotValidModN,
			expected: "pedersen: S and T must be in [1,…,N-1] and coprime to N",
		},
	}

	for _, tc := range tests {
		t.Run(string(tc.err), func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.err.Error())
		})
	}
}

// Test with identity elements
func TestIdentityElements(t *testing.T) {
	params := benchParams

	// Test commitment with x=0, y=0 should give 1 (in the group)
	x := new(saferith.Int).SetUint64(0)
	y := new(saferith.Int).SetUint64(0)

	commitment := params.Commit(x, y)

	// s^0 * t^0 = 1 * 1 = 1 (mod N)
	// The result should be 1 in the Montgomery representation
	// Just verify it's not nil and is valid
	assert.NotNil(t, commitment)
	assert.True(t, arith.IsValidNatModN(benchN, commitment))

	// Verify it equals 1 by checking s^0 * t^0
	s0 := params.n.ExpI(params.s, new(saferith.Int).SetUint64(0))
	t0 := params.n.ExpI(params.t, new(saferith.Int).SetUint64(0))
	expected := s0.ModMul(s0, t0, benchN)

	assert.Equal(t, expected, commitment, "Commit(0,0) should equal s^0 * t^0")
}

// Test verification with correct witness
func TestVerifyWithCorrectWitness(t *testing.T) {
	params := benchParams

	// Create a commitment and its opening
	x := new(saferith.Int).SetUint64(123)
	y := new(saferith.Int).SetUint64(456)

	commitment := params.Commit(x, y)

	// Verify with correct witness (e=0 case)
	e := new(saferith.Int).SetUint64(0)
	T := new(saferith.Nat).SetUint64(1)

	result := params.Verify(x, y, e, commitment, T)
	assert.True(t, result, "Verification with correct witness should succeed")
}

// Test large values
func TestLargeValues(t *testing.T) {
	params := benchParams

	// Create large values (but still smaller than modulus)
	largeBytes := make([]byte, 100)
	for i := range largeBytes {
		largeBytes[i] = byte(i % 256)
	}

	x := new(saferith.Int).SetBytes(largeBytes)
	y := new(saferith.Int).SetBytes(largeBytes)

	// Should not panic
	commitment := params.Commit(x, y)
	assert.NotNil(t, commitment)

	// Verify it's in valid range
	assert.True(t, arith.IsValidNatModN(benchN, commitment))
}

// Test edge cases in Verify
func TestVerifyEdgeCases(t *testing.T) {
	params := benchParams

	// Test with all zeros (except S and T which must be non-zero)
	a := new(saferith.Int).SetUint64(0)
	b := new(saferith.Int).SetUint64(0)
	e := new(saferith.Int).SetUint64(0)
	S := new(saferith.Nat).SetUint64(1)
	T := new(saferith.Nat).SetUint64(1)

	result := params.Verify(a, b, e, S, T)
	assert.True(t, result, "Verify(0,0,0,1,1) should be true")

	// Test with S = T = 1 and e = 1
	e1 := new(saferith.Int).SetUint64(1)
	result = params.Verify(a, b, e1, S, T)
	assert.True(t, result, "Verify(0,0,1,1,1) should be true")
}
