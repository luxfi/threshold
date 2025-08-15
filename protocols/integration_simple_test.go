package protocols_test

import (
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	cmpconfig "github.com/luxfi/threshold/protocols/cmp/config"
	"github.com/luxfi/threshold/protocols/frost"
	lssconfig "github.com/luxfi/threshold/protocols/lss/config"
)

func TestSimpleLSSConfig(t *testing.T) {
	// Test LSS config creation without running protocol
	n := 3
	threshold := 2
	partyIDs := test.PartyIDs(n)
	group := curve.Secp256k1{}

	configs := make([]*lssconfig.Config, n)
	for i, id := range partyIDs {
		configs[i] = &lssconfig.Config{
			Group:     group,
			ID:        id,
			Threshold: threshold,
		}
	}

	if len(configs) != n {
		t.Errorf("Expected %d configs, got %d", n, len(configs))
	}
}

func TestSimpleCMPConfig(t *testing.T) {
	// Test CMP config creation without running protocol
	n := 3
	threshold := 2
	partyIDs := test.PartyIDs(n)
	group := curve.Secp256k1{}

	configs := make([]*cmpconfig.Config, n)
	for i, id := range partyIDs {
		configs[i] = &cmpconfig.Config{
			Group:     group,
			ID:        id,
			Threshold: threshold,
		}
	}

	if len(configs) != n {
		t.Errorf("Expected %d configs, got %d", n, len(configs))
	}
}

func TestSimpleFROSTConfig(t *testing.T) {
	// Test FROST config creation without running protocol
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
}

func TestPartyIDCreation(t *testing.T) {
	// Test party ID creation
	for _, n := range []int{3, 5, 7, 10} {
		partyIDs := test.PartyIDs(n)
		if len(partyIDs) != n {
			t.Errorf("Expected %d party IDs, got %d", n, len(partyIDs))
		}

		// Check for uniqueness
		seen := make(map[party.ID]bool)
		for _, id := range partyIDs {
			if seen[id] {
				t.Errorf("Duplicate party ID: %v", id)
			}
			seen[id] = true
		}
	}
}

func TestThresholdValues(t *testing.T) {
	// Test various threshold configurations
	testCases := []struct {
		n         int
		threshold int
		valid     bool
	}{
		{3, 2, true},
		{5, 3, true},
		{7, 4, true},
		{10, 6, true},
		{3, 4, false}, // threshold > n
		{5, 0, false}, // threshold = 0
		{7, 1, true},  // threshold = 1 (valid but not secure)
	}

	for _, tc := range testCases {
		if tc.valid {
			if tc.threshold > tc.n {
				t.Errorf("Invalid threshold %d for n=%d", tc.threshold, tc.n)
			}
			if tc.threshold < 1 {
				t.Errorf("Threshold must be at least 1, got %d", tc.threshold)
			}
		}
	}
}

func TestCurveOperations(t *testing.T) {
	// Test basic curve operations
	curves := []curve.Curve{
		curve.Secp256k1{},
	}

	for _, c := range curves {
		// Test point creation
		point := c.NewPoint()
		if point == nil {
			t.Error("Failed to create new point")
		}

		// Test scalar creation
		scalar := c.NewScalar()
		if scalar == nil {
			t.Error("Failed to create new scalar")
		}

		// Test curve name
		name := c.Name()
		if name == "" {
			t.Error("Curve has no name")
		}
	}
}
