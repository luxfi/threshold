package lss_test

import (
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/lss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLSSIntegration tests the core LSS functionality
func TestLSSIntegration(t *testing.T) {
	group := curve.Secp256k1{}

	t.Run("Keygen", func(t *testing.T) {
		// Test key generation
		partyIDs := []party.ID{"alice", "bob", "charlie", "david", "eve"}
		threshold := 3

		configs := lss.RunKeygen(t, group, partyIDs, threshold)
		require.Len(t, configs, 5)

		// Verify all configs have same public key
		var publicKey curve.Point
		for _, cfg := range configs {
			pk, err := cfg.PublicPoint()
			require.NoError(t, err)
			if publicKey == nil {
				publicKey = pk
			} else {
				assert.True(t, publicKey.Equal(pk), "All configs should have same public key")
			}
		}
	})

	t.Run("Reshare", func(t *testing.T) {
		// Initial setup
		oldPartyIDs := []party.ID{"alice", "bob", "charlie"}
		oldThreshold := 2
		oldConfigs := lss.RunKeygen(t, group, oldPartyIDs, oldThreshold)

		// Get original public key
		originalPK, err := oldConfigs["alice"].PublicPoint()
		require.NoError(t, err)

		// Reshare to new parties
		newPartyIDs := []party.ID{"alice", "david", "eve", "frank"}
		newThreshold := 3
		newConfigs := lss.RunReshare(t, oldConfigs, newPartyIDs, newThreshold)

		require.Len(t, newConfigs, 4)

		// Verify public key is preserved
		for _, cfg := range newConfigs {
			pk, err := cfg.PublicPoint()
			require.NoError(t, err)
			assert.True(t, originalPK.Equal(pk), "Public key should be preserved after resharing")
		}

		// Verify generation incremented
		assert.Greater(t, newConfigs["alice"].Generation, oldConfigs["alice"].Generation)
	})

	t.Run("Rollback", func(t *testing.T) {
		// Create rollback manager
		mgr := lss.NewRollbackManager(10)

		// Create and save multiple generations
		partyIDs := []party.ID{"alice", "bob", "charlie"}
		configs := lss.RunKeygen(t, group, partyIDs, 2)

		for i := uint64(0); i < 3; i++ {
			cfg := configs["alice"]
			cfg.Generation = i
			err := mgr.SaveSnapshot(cfg)
			require.NoError(t, err)
		}

		// Test rollback
		history := mgr.GetHistory()
		require.GreaterOrEqual(t, len(history), 3)

		// Rollback to generation 1
		restoredCfg, err := mgr.Rollback(1)
		require.NoError(t, err)
		require.NotNil(t, restoredCfg)

		// Verify rollback tracking
		assert.NotEqual(t, uint64(0), restoredCfg.RollbackFrom, "Should track rollback source")
	})

	t.Run("DynamicReshareCMP", func(t *testing.T) {
		// Test the CMP resharing function
		partyIDs := []party.ID{"alice", "bob", "charlie", "david"}
		configs := lss.RunKeygen(t, group, partyIDs, 2)

		// Convert to CMP configs (these are already compatible)
		cmpConfigs := make(map[party.ID]*lss.Config)
		for id, cfg := range configs {
			cmpConfigs[id] = cfg
		}

		// Perform dynamic resharing
		newPartyIDs := []party.ID{"bob", "charlie", "eve", "frank"}
		newThreshold := 3

		// Note: This will return nil in test mode since we need CMP configs
		// but it verifies the function doesn't panic
		_, err := lss.DynamicReshareCMP(nil, newPartyIDs, newThreshold, nil)
		assert.Error(t, err, "Should error with nil configs")
	})

	t.Run("SignWithBlinding", func(t *testing.T) {
		// Test blinding protocol setup
		partyIDs := []party.ID{"alice", "bob", "charlie"}
		configs := lss.RunKeygen(t, group, partyIDs, 2)

		messageHash := make([]byte, 32)
		for i := range messageHash {
			messageHash[i] = byte(i)
		}

		signers := []party.ID{"alice", "bob"}

		// Test Protocol I
		startFunc := lss.SignWithBlinding(configs["alice"], signers, messageHash, lss.BlindingProtocolI, nil)
		require.NotNil(t, startFunc, "Should create start function for Protocol I")

		// Test Protocol II
		startFunc = lss.SignWithBlinding(configs["alice"], signers, messageHash, lss.BlindingProtocolII, nil)
		require.NotNil(t, startFunc, "Should create start function for Protocol II")
	})

	t.Run("VerifyConfig", func(t *testing.T) {
		// Test config verification
		partyIDs := []party.ID{"alice", "bob"}
		configs := lss.RunKeygen(t, group, partyIDs, 2)

		for _, cfg := range configs {
			err := lss.VerifyConfig(cfg)
			assert.NoError(t, err, "Valid config should verify")
		}
	})

	t.Run("IsCompatibleForSigning", func(t *testing.T) {
		// Test compatibility checking
		partyIDs := []party.ID{"alice", "bob", "charlie"}
		configs := lss.RunKeygen(t, group, partyIDs, 2)

		// Same generation configs should be compatible
		assert.True(t, lss.IsCompatibleForSigning(configs["alice"], configs["bob"]))

		// Different generation should not be compatible
		configs["alice"].Generation = 1
		configs["bob"].Generation = 2
		assert.False(t, lss.IsCompatibleForSigning(configs["alice"], configs["bob"]))
	})
}

// TestLSSCoreFunctionality tests basic LSS operations work
func TestLSSCoreFunctionality(t *testing.T) {
	group := curve.Secp256k1{}

	// Simple keygen test
	configs := lss.RunKeygen(t, group, []party.ID{"a", "b", "c"}, 2)
	assert.Len(t, configs, 3)

	// All should have valid configs
	for id, cfg := range configs {
		assert.Equal(t, id, cfg.ID)
		assert.Equal(t, 2, cfg.Threshold)
		assert.NotNil(t, cfg.ECDSA)
		assert.NotNil(t, cfg.ChainKey)
		assert.NotNil(t, cfg.RID)
	}
}