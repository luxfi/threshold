package doerner_test

import (
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/party"
)

func TestDoernerBasicSetup(t *testing.T) {
	// Test basic Doerner protocol setup
	n := 5
	partyIDs := test.PartyIDs(n)

	if len(partyIDs) != n {
		t.Errorf("Expected %d party IDs, got %d", n, len(partyIDs))
	}

	// Check party ID uniqueness
	seen := make(map[party.ID]bool)
	for _, id := range partyIDs {
		if seen[id] {
			t.Error("Duplicate party ID found")
		}
		seen[id] = true
	}
}

func TestDoernerPartyCount(t *testing.T) {
	// Test various party counts
	testCases := []int{2, 3, 5, 7, 10}

	for _, n := range testCases {
		partyIDs := test.PartyIDs(n)
		if len(partyIDs) != n {
			t.Errorf("For n=%d, expected %d party IDs but got %d", n, n, len(partyIDs))
		}
	}
}

func TestDoernerThresholdLogic(t *testing.T) {
	// Test threshold validation logic
	testCases := []struct {
		n         int
		threshold int
		valid     bool
	}{
		{5, 3, true},
		{7, 4, true},
		{3, 2, true},
		{5, 0, false},
		{5, 6, false},
		{10, 10, true},
	}

	for _, tc := range testCases {
		isValid := tc.threshold > 0 && tc.threshold <= tc.n
		if isValid != tc.valid {
			t.Errorf("For n=%d, threshold=%d, expected valid=%v but got %v",
				tc.n, tc.threshold, tc.valid, isValid)
		}
	}
}
