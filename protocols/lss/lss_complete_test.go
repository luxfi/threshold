package lss_test

import (
	"testing"
	"time"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/lss"
	"github.com/luxfi/threshold/protocols/lss/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLSSCompleteFlow tests the complete LSS protocol flow: keygen, refresh, and sign
func TestLSSCompleteFlow(t *testing.T) {
	// Setup
	N := 5
	T := 3
	partyIDs := test.PartyIDs(N)
	pl := pool.NewPool(0)
	defer pl.TearDown()
	
	t.Run("Keygen", func(t *testing.T) {
		// Run keygen protocol
		configs := runKeygen(t, partyIDs, T, pl)
		
		// Verify all parties have the same public key
		pubKey0, err := configs[0].PublicPoint()
		require.NoError(t, err)
		for i := 1; i < N; i++ {
			pubKeyI, err := configs[i].PublicPoint()
			require.NoError(t, err)
			assert.True(t, pubKey0.Equal(pubKeyI),
				"All parties should have the same public key")
		}
		
		// Verify threshold is correct
		assert.Equal(t, T, configs[0].Threshold)
		
		t.Run("Refresh", func(t *testing.T) {
			// Run refresh protocol
			newConfigs := runRefresh(t, partyIDs, configs, pl)
			
			// Verify public key unchanged
			for i := 0; i < N; i++ {
				pubKeyOld, err := configs[i].PublicPoint()
				require.NoError(t, err)
				pubKeyNew, err := newConfigs[i].PublicPoint()
				require.NoError(t, err)
				assert.True(t, pubKeyOld.Equal(pubKeyNew),
					"Public key should remain unchanged after refresh")
			}
			
			t.Run("Sign", func(t *testing.T) {
				// Test message
				message := []byte("test message for LSS protocol")
				
				// Select signers (threshold subset)
				signers := partyIDs[:T]
				signerConfigs := make(map[party.ID]*config.Config)
				for _, id := range signers {
					for j, pid := range partyIDs {
						if pid == id {
							signerConfigs[id] = newConfigs[j]
							break
						}
					}
				}
				
				// Run sign protocol
				signature := runSign(t, signers, signerConfigs, message, pl)
				
				// Verify signature
				publicKey, err := newConfigs[0].PublicPoint()
				require.NoError(t, err)
				assert.True(t, signature.Verify(publicKey, message),
					"Signature should verify with public key")
			})
		})
	})
}

// runKeygen runs the LSS keygen protocol and returns configs for all parties
func runKeygen(t *testing.T, partyIDs []party.ID, threshold int, pl *pool.Pool) []*config.Config {
	results, err := test.RunProtocol(t, partyIDs, nil, func(id party.ID) protocol.StartFunc {
		return lss.Keygen(curve.Secp256k1{}, id, partyIDs, threshold, pl)
	})
	require.NoError(t, err, "Keygen should complete successfully")
	
	configs := make([]*config.Config, len(partyIDs))
	for i, id := range partyIDs {
		config, ok := results[id].(*config.Config)
		require.True(t, ok, "Result should be a Config")
		require.NotNil(t, config, "Config should not be nil")
		configs[i] = config
	}
	
	return configs
}

// runRefresh runs the LSS refresh protocol
func runRefresh(t *testing.T, partyIDs []party.ID, configs []*config.Config, pl *pool.Pool) []*config.Config {
	// Create new party set (could be different from original)
	newPartyIDs := partyIDs // For simplicity, using same parties
	
	results, err := test.RunProtocol(t, newPartyIDs, nil, func(id party.ID) protocol.StartFunc {
		// Find config for this party
		var config *config.Config
		for i, pid := range partyIDs {
			if pid == id {
				config = configs[i]
				break
			}
		}
		require.NotNil(t, config, "Config should exist for party %s", id)
		
		return lss.Refresh(config, pl)
	})
	require.NoError(t, err, "Refresh should complete successfully")
	
	newConfigs := make([]*config.Config, len(newPartyIDs))
	for i, id := range newPartyIDs {
		config, ok := results[id].(*config.Config)
		require.True(t, ok, "Result should be a Config")
		require.NotNil(t, config, "Config should not be nil")
		newConfigs[i] = config
	}
	
	return newConfigs
}

// runSign runs the LSS sign protocol
func runSign(t *testing.T, signers []party.ID, configs map[party.ID]*config.Config, message []byte, pl *pool.Pool) *ecdsa.Signature {
	results, err := test.RunProtocol(t, signers, nil, func(id party.ID) protocol.StartFunc {
		config := configs[id]
		require.NotNil(t, config, "Config should exist for signer %s", id)
		
		return lss.Sign(config, signers, message, pl)
	})
	require.NoError(t, err, "Sign should complete successfully")
	
	// All signers should produce the same signature
	var signature *ecdsa.Signature
	for _, result := range results {
		sig, ok := result.(*ecdsa.Signature)
		require.True(t, ok, "Result should be a Signature")
		require.NotNil(t, sig, "Signature should not be nil")
		
		if signature == nil {
			signature = sig
		} else {
			// Verify all signers produced the same signature
			assert.True(t, signature.R.Equal(sig.R), "R values should match")
			assert.True(t, signature.S.Equal(sig.S), "S values should match")
		}
	}
	
	return signature
}

// TestLSSKeygenSimple tests just the keygen phase
func TestLSSKeygenSimple(t *testing.T) {
	N := 3
	T := 2
	partyIDs := test.PartyIDs(N)
	pl := pool.NewPool(0)
	defer pl.TearDown()
	
	// Set a timeout for the test
	timeout := time.After(10 * time.Second)
	done := make(chan bool)
	
	go func() {
		configs := runKeygen(t, partyIDs, T, pl)
		
		// Basic verification
		require.Len(t, configs, N)
		for i := 0; i < N; i++ {
			require.NotNil(t, configs[i])
			pubKey, err := configs[i].PublicPoint()
			require.NoError(t, err)
			require.NotNil(t, pubKey)
		}
		
		done <- true
	}()
	
	select {
	case <-timeout:
		t.Fatal("Test timed out")
	case <-done:
		// Test completed successfully
	}
}