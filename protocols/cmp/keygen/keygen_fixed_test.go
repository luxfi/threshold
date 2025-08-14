package keygen_test

import (
	"testing"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/cmp/config"
	"github.com/luxfi/threshold/protocols/cmp/keygen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKeygenReliable tests CMP keygen with proper timeout handling
func TestKeygenReliable(t *testing.T) {
	N := 5
	threshold := N - 1
	partyIDs := test.PartyIDs(N)
	group := curve.Secp256k1{}

	// Use test config with appropriate timeouts
	testConfig := test.DefaultTestConfig()
	runner := test.NewRunner(t, testConfig)
	defer runner.Cleanup()

	// Create start functions for each party with their own pool
	sessionID := []byte("cmp-keygen-test")
	startFuncs := make(map[party.ID]protocol.StartFunc)
	pools := make([]*pool.Pool, 0, N)
	
	for _, id := range partyIDs {
		pl := pool.NewPool(0)
		pools = append(pools, pl)
		
		info := round.Info{
			ProtocolID:       "cmp/keygen-test",
			FinalRoundNumber: keygen.Rounds,
			SelfID:           id,
			PartyIDs:         partyIDs,
			Threshold:        threshold,
			Group:            group,
		}
		startFuncs[id] = keygen.Start(info, pl, nil)
	}
	
	// Cleanup pools after test
	defer func() {
		for _, pl := range pools {
			pl.TearDown()
		}
	}()

	// Setup parties
	err := runner.SetupParties(partyIDs, startFuncs, sessionID)
	require.NoError(t, err, "failed to setup parties")

	// Run protocol
	err = runner.Run()
	require.NoError(t, err, "protocol execution failed")

	// Verify results
	results := runner.Results()
	require.Len(t, results, N, "expected results from all parties")

	// Check that all configs are valid
	configs := make(map[party.ID]*config.Config)
	for id, result := range results {
		cfg, ok := result.(*config.Config)
		require.True(t, ok, "result should be a config")
		require.NotNil(t, cfg, "config should not be nil")
		configs[id] = cfg
	}

	// Verify configs are consistent
	verifyConfigs(t, configs)
}

// TestRefreshReliable tests CMP refresh with proper timeout handling
func TestRefreshReliable(t *testing.T) {
	N := 4
	threshold := N - 1
	partyIDs := test.PartyIDs(N)
	group := curve.Secp256k1{}

	// First run keygen to get configs
	configs := runKeygen(t, N, threshold, nil)
	require.Len(t, configs, N, "keygen should produce configs for all parties")

	// Now run refresh with existing configs
	testConfig := test.DefaultTestConfig()
	runner := test.NewRunner(t, testConfig)
	defer runner.Cleanup()

	sessionID := []byte("cmp-refresh-test")
	startFuncs := make(map[party.ID]protocol.StartFunc)
	pools := make([]*pool.Pool, 0, N)
	
	for id, cfg := range configs {
		pl := pool.NewPool(0)
		pools = append(pools, pl)
		
		info := round.Info{
			ProtocolID:       "cmp/refresh-test",
			FinalRoundNumber: keygen.Rounds,
			SelfID:           id,
			PartyIDs:         partyIDs,
			Threshold:        threshold,
			Group:            group,
		}
		startFuncs[id] = keygen.Start(info, pl, cfg)
	}
	
	// Cleanup pools after test
	defer func() {
		for _, pl := range pools {
			pl.TearDown()
		}
	}()

	// Setup parties
	err := runner.SetupParties(partyIDs, startFuncs, sessionID)
	require.NoError(t, err, "failed to setup parties")

	// Run protocol
	err = runner.Run()
	require.NoError(t, err, "refresh protocol failed")

	// Verify results
	results := runner.Results()
	require.Len(t, results, N, "expected refreshed configs from all parties")

	// Check refreshed configs
	refreshedConfigs := make(map[party.ID]*config.Config)
	for id, result := range results {
		cfg, ok := result.(*config.Config)
		require.True(t, ok, "result should be a config")
		require.NotNil(t, cfg, "refreshed config should not be nil")
		refreshedConfigs[id] = cfg
	}

	// Verify refreshed configs
	verifyConfigs(t, refreshedConfigs)
	
	// Verify that group key hasn't changed
	for id := range configs {
		oldGroupKey := configs[id].PublicPoint()
		newGroupKey := refreshedConfigs[id].PublicPoint()
		assert.True(t, oldGroupKey.Equal(newGroupKey), 
			"group public key should remain the same after refresh")
	}
}

// Helper function to run keygen and return configs
func runKeygen(t *testing.T, N, threshold int, _ *pool.Pool) map[party.ID]*config.Config {
	partyIDs := test.PartyIDs(N)
	group := curve.Secp256k1{}

	testConfig := test.DefaultTestConfig()
	runner := test.NewRunner(t, testConfig)
	defer runner.Cleanup()

	sessionID := []byte("cmp-keygen-helper")
	startFuncs := make(map[party.ID]protocol.StartFunc)
	pools := make([]*pool.Pool, 0, N)
	
	for _, id := range partyIDs {
		pl := pool.NewPool(0)
		pools = append(pools, pl)
		
		info := round.Info{
			ProtocolID:       "cmp/keygen-helper",
			FinalRoundNumber: keygen.Rounds,
			SelfID:           id,
			PartyIDs:         partyIDs,
			Threshold:        threshold,
			Group:            group,
		}
		startFuncs[id] = keygen.Start(info, pl, nil)
	}
	
	// Cleanup pools after test
	defer func() {
		for _, pl := range pools {
			pl.TearDown()
		}
	}()

	err := runner.SetupParties(partyIDs, startFuncs, sessionID)
	require.NoError(t, err)

	err = runner.Run()
	require.NoError(t, err)

	results := runner.Results()
	configs := make(map[party.ID]*config.Config)
	for id, result := range results {
		cfg := result.(*config.Config)
		configs[id] = cfg
	}
	
	return configs
}

// Helper function to verify configs are consistent
func verifyConfigs(t *testing.T, configs map[party.ID]*config.Config) {
	// Get the first config as reference
	var refConfig *config.Config
	var refID party.ID
	for id, cfg := range configs {
		refConfig = cfg
		refID = id
		break
	}

	// All parties should have the same group public key
	groupKey := refConfig.PublicPoint()
	
	for id, cfg := range configs {
		if id == refID {
			continue
		}
		
		// Check group public key matches
		assert.True(t, groupKey.Equal(cfg.PublicPoint()),
			"party %s has different group key than party %s", id, refID)
		
		// Check threshold matches
		assert.Equal(t, refConfig.Threshold, cfg.Threshold,
			"party %s has different threshold than party %s", id, refID)
		
		// Check that each party has their own secret
		assert.NotNil(t, cfg.ECDSA, "party %s should have ECDSA secret", id)
		assert.NotNil(t, cfg.Paillier, "party %s should have Paillier secret", id)
		assert.NotNil(t, cfg.ElGamal, "party %s should have ElGamal secret", id)
		
		// Check RID and ChainKey are set
		assert.NotNil(t, cfg.RID, "party %s should have RID", id)
		assert.NotNil(t, cfg.ChainKey, "party %s should have ChainKey", id)
	}
}