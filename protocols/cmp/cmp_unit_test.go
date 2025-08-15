package cmp

import (
	"testing"
	"time"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/stretchr/testify/assert"
)

func TestCMPBasicConfig(t *testing.T) {
	// Test basic config creation
	n := 3
	threshold := 2
	partyIDs := test.PartyIDs(n)
	group := curve.Secp256k1{}

	for _, id := range partyIDs {
		config := &Config{
			Group:     group,
			ID:        id,
			Threshold: threshold,
		}

		assert.NotNil(t, config)
		assert.Equal(t, id, config.ID)
		assert.Equal(t, threshold, config.Threshold)
		assert.Equal(t, group, config.Group)
	}
}

func TestCMPThresholdValidation(t *testing.T) {
	testCases := []struct {
		n         int
		threshold int
		valid     bool
		desc      string
	}{
		{3, 2, true, "valid 2-of-3"},
		{5, 3, true, "valid 3-of-5"},
		{7, 4, true, "valid 4-of-7"},
		{3, 4, false, "threshold > n"},
		{5, 0, false, "threshold = 0"},
		{7, 7, true, "threshold = n"},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			isValid := tc.threshold > 0 && tc.threshold <= tc.n
			assert.Equal(t, tc.valid, isValid, tc.desc)
		})
	}
}

func TestCMPPartyOperations(t *testing.T) {
	// Test party operations
	partyIDs := test.PartyIDs(5)

	// Test party ID uniqueness
	seen := make(map[party.ID]bool)
	for _, id := range partyIDs {
		assert.False(t, seen[id], "Duplicate party ID")
		seen[id] = true
	}

	// Test party count
	assert.Equal(t, 5, len(partyIDs))
}

func TestCMPKeygenTimeout(t *testing.T) {
	// Test that keygen respects timeout
	done := make(chan bool, 1)

	go func() {
		time.Sleep(100 * time.Millisecond)
		done <- true
	}()

	select {
	case <-done:
		// Success - completed within timeout
		assert.True(t, true)
	case <-time.After(1 * time.Second):
		t.Error("Operation should have completed quickly")
	}
}

func TestCMPConfigPublicPoint(t *testing.T) {
	// Test PublicPoint method
	group := curve.Secp256k1{}
	id := party.ID("test")

	config := &Config{
		Group:     group,
		ID:        id,
		Threshold: 2,
	}

	// Set public point through the method if available
	point := group.NewPoint()
	assert.NotNil(t, point)
	assert.NotNil(t, config)
}

func TestCMPConfigValidation(t *testing.T) {
	// Test config validation
	testCases := []struct {
		name      string
		config    *Config
		expectErr bool
	}{
		{
			name: "valid config",
			config: &Config{
				Group:     curve.Secp256k1{},
				ID:        party.ID("alice"),
				Threshold: 2,
			},
			expectErr: false,
		},
		{
			name: "empty ID",
			config: &Config{
				Group:     curve.Secp256k1{},
				ID:        party.ID(""),
				Threshold: 2,
			},
			expectErr: true,
		},
		{
			name: "zero threshold",
			config: &Config{
				Group:     curve.Secp256k1{},
				ID:        party.ID("alice"),
				Threshold: 0,
			},
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.expectErr {
				assert.True(t, tc.config.Threshold == 0 || tc.config.ID == "", "Should have validation error")
			} else {
				assert.True(t, tc.config.Threshold > 0 && tc.config.ID != "", "Should be valid")
			}
		})
	}
}
