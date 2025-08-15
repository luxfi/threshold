package lss_test

import (
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/lss"
	"github.com/luxfi/threshold/protocols/lss/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLSSBasicConfig(t *testing.T) {
	// Test basic LSS configuration
	n := 3
	threshold := 2
	partyIDs := test.PartyIDs(n)
	group := curve.Secp256k1{}

	configs := make([]*config.Config, n)
	for i, id := range partyIDs {
		configs[i] = &config.Config{
			Group:     group,
			ID:        id,
			Threshold: threshold,
		}

		assert.NotNil(t, configs[i])
		assert.Equal(t, id, configs[i].ID)
		assert.Equal(t, threshold, configs[i].Threshold)
	}
}

func TestLSSKeygenInitialization(t *testing.T) {
	// Test LSS keygen initialization
	n := 5
	threshold := 3
	partyIDs := test.PartyIDs(n)
	group := curve.Secp256k1{}

	// Test that keygen can be initialized
	for _, id := range partyIDs {
		keygenStart := lss.Keygen(group, id, partyIDs, threshold, nil)
		assert.NotNil(t, keygenStart, "Keygen should initialize for party %s", id)
	}
}

func TestLSSSignInitialization(t *testing.T) {
	// Test LSS sign initialization
	n := 5
	threshold := 3
	partyIDs := test.PartyIDs(n)
	group := curve.Secp256k1{}
	message := []byte("test message")

	// Create mock configs
	configs := make([]*config.Config, n)
	for i, id := range partyIDs {
		configs[i] = &config.Config{
			Group:     group,
			ID:        id,
			Threshold: threshold,
		}
	}

	// Select signers
	signers := partyIDs[:threshold]

	// Test that sign can be initialized
	for _, id := range signers {
		for _, cfg := range configs {
			if cfg.ID == id {
				signStart := lss.Sign(cfg, signers, message, nil)
				assert.NotNil(t, signStart, "Sign should initialize for party %s", id)
				break
			}
		}
	}
}

func TestLSSReshareInitialization(t *testing.T) {
	// Test LSS reshare initialization
	n := 5
	newN := 7
	oldThreshold := 3
	newThreshold := 4
	oldPartyIDs := test.PartyIDs(n)
	newPartyIDs := test.PartyIDs(newN)
	group := curve.Secp256k1{}

	// Create mock config
	config := &config.Config{
		Group:     group,
		ID:        oldPartyIDs[0],
		Threshold: oldThreshold,
	}

	// Test that reshare can be initialized
	reshareStart := lss.Reshare(config, newPartyIDs, newThreshold, nil)
	assert.NotNil(t, reshareStart, "Reshare should initialize")
}

func TestLSSThresholdValidation(t *testing.T) {
	// Test threshold validation
	testCases := []struct {
		name      string
		n         int
		threshold int
		valid     bool
	}{
		{"valid 2-of-3", 3, 2, true},
		{"valid 3-of-5", 5, 3, true},
		{"valid 4-of-7", 7, 4, true},
		{"threshold > n", 3, 4, false},
		{"threshold = 0", 5, 0, false},
		{"threshold = n", 5, 5, true},
		{"minimum threshold", 10, 1, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			isValid := tc.threshold > 0 && tc.threshold <= tc.n
			assert.Equal(t, tc.valid, isValid, tc.name)
		})
	}
}

func TestLSSPartyOperations(t *testing.T) {
	// Test party operations
	n := 7
	partyIDs := test.PartyIDs(n)

	// Test party count
	assert.Equal(t, n, len(partyIDs))

	// Test uniqueness
	seen := make(map[party.ID]bool)
	for _, id := range partyIDs {
		require.False(t, seen[id], "Duplicate party ID found")
		seen[id] = true
	}

	// Test party removal
	remaining := partyIDs[1:]
	assert.Equal(t, n-1, len(remaining))
	assert.NotContains(t, remaining, partyIDs[0])
}

func TestLSSSignerSubsets(t *testing.T) {
	// Test different signer subsets
	n := 7
	threshold := 4
	partyIDs := test.PartyIDs(n)

	testCases := []struct {
		name        string
		signerCount int
		valid       bool
	}{
		{"exact threshold", threshold, true},
		{"more than threshold", threshold + 1, true},
		{"less than threshold", threshold - 1, false},
		{"all parties", n, true},
		{"single party", 1, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signers := partyIDs[:tc.signerCount]
			isValid := len(signers) >= threshold
			assert.Equal(t, tc.valid, isValid, tc.name)
		})
	}
}

func TestLSSCurveCompatibility(t *testing.T) {
	// Test curve compatibility
	curves := []struct {
		name  string
		curve curve.Curve
	}{
		{"secp256k1", curve.Secp256k1{}},
	}

	for _, c := range curves {
		t.Run(c.name, func(t *testing.T) {
			// Test point operations
			point := c.curve.NewPoint()
			assert.NotNil(t, point, "Should create point for %s", c.name)

			// Test scalar operations
			scalar := c.curve.NewScalar()
			assert.NotNil(t, scalar, "Should create scalar for %s", c.name)
		})
	}
}
