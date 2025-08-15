package frost

import (
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFrostKeygenOnly(t *testing.T) {
	N := 5
	T := N - 1

	partyIDs := test.PartyIDs(N)

	// Use the improved harness
	harness := test.NewHarness(t, partyIDs)
	sessionID := []byte("test-keygen-session")

	// Create handlers for all parties
	for _, id := range partyIDs {
		startFunc := Keygen(curve.Secp256k1{}, id, partyIDs, T)
		_, err := harness.CreateHandler(id, startFunc, sessionID)
		require.NoError(t, err)
	}

	// Run the protocol
	err := harness.Run()
	require.NoError(t, err)

	// Get results
	results := harness.Results()
	configs := make([]*Config, N)
	for i, id := range partyIDs {
		r, ok := results[id]
		require.True(t, ok, "Should have result for party %s", id)
		require.IsType(t, &Config{}, r)
		configs[i] = r.(*Config)
	}

	// Verify all have same public key
	require.NotNil(t, configs[0], "First config should not be nil")
	require.NotNil(t, configs[0].PublicKey, "Public key should not be nil")

	for i := 1; i < N; i++ {
		require.NotNil(t, configs[i], "Config %d should not be nil", i)
		require.NotNil(t, configs[i].PublicKey, "Public key %d should not be nil", i)
		assert.True(t, configs[0].PublicKey.Equal(configs[i].PublicKey))
	}
}

func TestFrostRefreshOnly(t *testing.T) {
	N := 3
	T := 2

	partyIDs := test.PartyIDs(N)

	// First do keygen to get configs
	harness1 := test.NewHarness(t, partyIDs)
	sessionID1 := []byte("test-keygen-session-1")

	// Create handlers for keygen
	for _, id := range partyIDs {
		startFunc := Keygen(curve.Secp256k1{}, id, partyIDs, T)
		_, err := harness1.CreateHandler(id, startFunc, sessionID1)
		require.NoError(t, err)
	}

	// Run keygen
	err := harness1.Run()
	require.NoError(t, err)

	// Get keygen results
	results1 := harness1.Results()
	configs := make([]*Config, N)
	for i, id := range partyIDs {
		r, ok := results1[id]
		require.True(t, ok, "Should have keygen result for party %s", id)
		require.IsType(t, &Config{}, r)
		configs[i] = r.(*Config)
	}

	// Check configs are valid
	require.NotNil(t, configs[0], "First config should not be nil after keygen")
	require.NotNil(t, configs[0].PublicKey, "Public key should not be nil after keygen")

	oldPublicKey := configs[0].PublicKey

	// Now do refresh with new harness and session
	harness2 := test.NewHarness(t, partyIDs)
	sessionID2 := []byte("test-refresh-session-2")

	// Create handlers for refresh
	for i, id := range partyIDs {
		startFunc := Refresh(configs[i], partyIDs)
		_, err := harness2.CreateHandler(id, startFunc, sessionID2)
		require.NoError(t, err)
	}

	// Run refresh
	err = harness2.Run()
	require.NoError(t, err)

	// Get refresh results
	results2 := harness2.Results()
	refreshedConfigs := make([]*Config, N)
	for i, id := range partyIDs {
		r, ok := results2[id]
		require.True(t, ok, "Should have refresh result for party %s", id)
		require.IsType(t, &Config{}, r)
		refreshedConfigs[i] = r.(*Config)
	}

	// Verify public key unchanged
	for i := 0; i < N; i++ {
		require.NotNil(t, refreshedConfigs[i], "Refreshed config %d should not be nil", i)
		require.NotNil(t, refreshedConfigs[i].PublicKey, "Refreshed public key %d should not be nil", i)
		assert.True(t, oldPublicKey.Equal(refreshedConfigs[i].PublicKey))
	}
}
