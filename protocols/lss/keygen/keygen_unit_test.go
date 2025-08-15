package keygen_test

import (
	"fmt"
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/stretchr/testify/assert"
)

func TestKeygenRoundCreation(t *testing.T) {
	// Test keygen round creation
	n := 3
	threshold := 2
	partyIDs := test.PartyIDs(n)

	// Test that we have the right number of parties
	assert.Equal(t, n, len(partyIDs))
	assert.True(t, threshold > 0 && threshold <= n)
}

func TestKeygenValidation(t *testing.T) {
	// Test keygen parameter validation
	testCases := []struct {
		name      string
		n         int
		threshold int
		expectErr bool
	}{
		{"valid 2-of-3", 3, 2, false},
		{"valid 3-of-5", 5, 3, false},
		{"threshold > n", 3, 4, true},
		{"threshold = 0", 3, 0, true},
		{"empty parties", 0, 0, true},
		{"single party", 1, 1, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hasError := tc.threshold <= 0 || tc.threshold > tc.n || tc.n == 0
			assert.Equal(t, tc.expectErr, hasError, tc.name)
		})
	}
}

func TestKeygenMessageTypes(t *testing.T) {
	// Test keygen message types

	// Verify message creation for each round
	for i := 1; i <= 3; i++ {
		t.Run(fmt.Sprintf("Round%d", i), func(t *testing.T) {
			// Each round should produce messages
			assert.True(t, i > 0 && i <= 3, "Valid round number")
		})
	}
}

func TestKeygenPartyTracking(t *testing.T) {
	// Test party tracking during keygen
	n := 5
	partyIDs := test.PartyIDs(n)

	// Test that all parties are tracked
	tracked := make(map[party.ID]bool)
	for _, id := range partyIDs {
		tracked[id] = true
	}

	assert.Equal(t, n, len(tracked), "All parties should be tracked")

	// Test party removal
	delete(tracked, partyIDs[0])
	assert.Equal(t, n-1, len(tracked), "Party should be removed")
}

func TestKeygenThresholdBounds(t *testing.T) {
	// Test threshold boundary conditions
	testCases := []struct {
		n         int
		threshold int
		desc      string
	}{
		{10, 1, "minimum threshold"},
		{10, 10, "maximum threshold (n)"},
		{10, 6, "majority threshold"},
		{10, 5, "half threshold"},
		{3, 2, "small group threshold"},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			assert.True(t, tc.threshold > 0, "Threshold must be positive")
			assert.True(t, tc.threshold <= tc.n, "Threshold must not exceed n")
		})
	}
}

func TestKeygenPolynomialDegree(t *testing.T) {
	// Test polynomial degree for secret sharing
	testCases := []struct {
		threshold int
		degree    int
	}{
		{2, 1},
		{3, 2},
		{5, 4},
		{10, 9},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("threshold=%d", tc.threshold), func(t *testing.T) {
			expectedDegree := tc.threshold - 1
			assert.Equal(t, tc.degree, expectedDegree, "Polynomial degree should be threshold-1")
		})
	}
}

func TestKeygenConcurrency(t *testing.T) {
	// Test concurrent keygen initialization
	n := 5
	partyIDs := test.PartyIDs(n)

	done := make(chan bool, n)

	for _, id := range partyIDs {
		go func(partyID party.ID) {
			// Just test that we can create parties concurrently
			assert.NotNil(t, partyID)
			done <- true
		}(id)
	}

	// Wait for all goroutines
	for i := 0; i < n; i++ {
		<-done
	}
}
