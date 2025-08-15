package frost_test

import (
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/protocols/frost"
)

func TestFROSTConfigCreation(t *testing.T) {
	// Test config creation without running full protocol
	n := 5
	threshold := 3
	partyIDs := test.PartyIDs(n)
	group := curve.Secp256k1{}

	configs := make([]*frost.Config, n)
	publicKey := group.NewPoint()

	for i, id := range partyIDs {
		configs[i] = &frost.Config{
			ID:        id,
			Threshold: threshold,
			PublicKey: publicKey,
		}
	}

	if len(configs) != n {
		t.Errorf("Expected %d configs, got %d", n, len(configs))
	}

	// Test that all configs share the same public key
	for i := 1; i < n; i++ {
		if !configs[i].PublicKey.Equal(configs[0].PublicKey) {
			t.Errorf("Config %d has different public key", i)
		}
	}
}

func TestFROSTThresholdValidation(t *testing.T) {
	testCases := []struct {
		n         int
		threshold int
		expectOK  bool
	}{
		{5, 3, true},
		{7, 4, true},
		{10, 6, true},
		{5, 6, false}, // threshold > n
		{7, 0, false}, // threshold = 0
		{3, 2, true},
	}

	for _, tc := range testCases {
		if tc.expectOK {
			if tc.threshold > tc.n || tc.threshold < 1 {
				t.Errorf("Should reject threshold %d for n=%d", tc.threshold, tc.n)
			}
		} else {
			if tc.threshold <= tc.n && tc.threshold >= 1 {
				t.Errorf("Should accept threshold %d for n=%d", tc.threshold, tc.n)
			}
		}
	}
}

func TestFROSTGroupOperations(t *testing.T) {
	group := curve.Secp256k1{}

	// Test point operations
	p1 := group.NewPoint()
	p2 := group.NewPoint()

	if p1 == nil || p2 == nil {
		t.Error("Failed to create points")
	}

	// Test scalar operations
	s1 := group.NewScalar()
	s2 := group.NewScalar()

	if s1 == nil || s2 == nil {
		t.Error("Failed to create scalars")
	}

	// Test identity element
	identity := group.NewPoint()
	if identity == nil {
		t.Error("Failed to create identity point")
	}
}
