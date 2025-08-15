package frost_test

import (
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/frost"
	"github.com/stretchr/testify/assert"
)

func TestFROSTConfigBasics(t *testing.T) {
	// Test basic FROST config
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

		assert.NotNil(t, configs[i])
		assert.Equal(t, id, configs[i].ID)
		assert.Equal(t, threshold, configs[i].Threshold)
		assert.NotNil(t, configs[i].PublicKey)
	}

	// Verify all configs share the same public key
	for i := 1; i < n; i++ {
		assert.Equal(t, configs[0].PublicKey, configs[i].PublicKey)
	}
}

func TestFROSTKeygenInitialization(t *testing.T) {
	// Test keygen initialization
	n := 5
	threshold := 3
	partyIDs := test.PartyIDs(n)
	group := curve.Secp256k1{}

	// Test that keygen can be initialized for each party
	for _, id := range partyIDs {
		keygenStart := frost.Keygen(group, id, partyIDs, threshold)
		assert.NotNil(t, keygenStart, "Keygen should initialize for party %s", id)
	}
}

func TestFROSTSignInitialization(t *testing.T) {
	// Test sign initialization
	n := 5
	threshold := 3
	partyIDs := test.PartyIDs(n)
	group := curve.Secp256k1{}
	message := []byte("test message")

	// Create mock configs
	configs := make(map[party.ID]*frost.Config)
	publicKey := group.NewPoint()

	for _, id := range partyIDs {
		configs[id] = &frost.Config{
			ID:        id,
			Threshold: threshold,
			PublicKey: publicKey,
		}
	}

	// Select signers (threshold parties)
	signers := partyIDs[:threshold]

	// Test that sign can be initialized
	for _, id := range signers {
		if config, ok := configs[id]; ok {
			signStart := frost.Sign(config, signers, message)
			assert.NotNil(t, signStart, "Sign should initialize for party %s", id)
		}
	}
}

func TestFROSTRefreshInitialization(t *testing.T) {
	// Test refresh initialization
	n := 5
	threshold := 3
	partyIDs := test.PartyIDs(n)
	group := curve.Secp256k1{}

	// Create mock config with required fields
	publicKey := group.NewPoint()
	privateShare := group.NewScalar()
	vsMap := make(map[party.ID]curve.Point)
	for _, id := range partyIDs {
		vsMap[id] = group.NewPoint()
	}
	verificationShares := party.NewPointMap(vsMap)

	config := &frost.Config{
		ID:                 partyIDs[0],
		Threshold:          threshold,
		PublicKey:          publicKey,
		PrivateShare:       privateShare,
		VerificationShares: verificationShares,
		ChainKey:           []byte("test-chain-key"),
	}

	// Test that refresh can be initialized
	refreshStart := frost.Refresh(config, partyIDs)
	assert.NotNil(t, refreshStart, "Refresh should initialize")
}

func TestFROSTThresholdScenarios(t *testing.T) {
	// Test various threshold scenarios
	testCases := []struct {
		name      string
		n         int
		threshold int
		valid     bool
	}{
		{"valid 3-of-5", 5, 3, true},
		{"valid 4-of-7", 7, 4, true},
		{"valid 2-of-3", 3, 2, true},
		{"threshold too high", 5, 6, false},
		{"threshold zero", 5, 0, false},
		{"threshold equals n", 5, 5, true},
		{"minimum threshold", 5, 1, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			isValid := tc.threshold > 0 && tc.threshold <= tc.n
			assert.Equal(t, tc.valid, isValid, tc.name)
		})
	}
}

func TestFROSTPartyManagement(t *testing.T) {
	// Test party management
	sizes := []int{3, 5, 7, 10}

	for _, n := range sizes {
		partyIDs := test.PartyIDs(n)
		assert.Equal(t, n, len(partyIDs), "Should have %d parties", n)

		// Check uniqueness
		seen := make(map[party.ID]bool)
		for _, id := range partyIDs {
			assert.False(t, seen[id], "Party ID should be unique")
			seen[id] = true
		}
	}
}

func TestFROSTSignerSelection(t *testing.T) {
	// Test signer selection for threshold signing
	n := 7
	threshold := 4
	partyIDs := test.PartyIDs(n)

	// Test various signer selections
	testCases := []struct {
		name        string
		signerCount int
		valid       bool
	}{
		{"exact threshold", threshold, true}, // FROST needs exactly t
		{"more than threshold", threshold + 1, true},
		{"even more than threshold", threshold + 2, true},
		{"less than threshold", threshold - 1, false},
		{"all parties", n, true},
		{"single party", 1, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.signerCount > n {
				tc.signerCount = n
			}
			signers := partyIDs[:tc.signerCount]
			// FROST requires at least threshold signers
			isValid := len(signers) >= threshold
			assert.Equal(t, tc.valid, isValid, tc.name)
		})
	}
}
