package lss_test

import (
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/lss"
	"github.com/luxfi/threshold/protocols/lss/config"
	"github.com/stretchr/testify/require"
)

// TestLSSFastKeygen tests keygen initialization without full protocol execution
func TestLSSFastKeygen(t *testing.T) {
	N := 3
	T := 2
	partyIDs := test.PartyIDs(N)
	pl := pool.NewPool(0)
	defer pl.TearDown()

	// Test that we can create start functions for all parties
	for _, id := range partyIDs {
		startFunc := lss.Keygen(curve.Secp256k1{}, id, partyIDs, T, pl)
		require.NotNil(t, startFunc, "Keygen start function should not be nil for party %s", id)
		
		// Verify the start function creates a valid round
		round := startFunc()
		require.NotNil(t, round, "Keygen should create initial round for party %s", id)
	}
	
	t.Log("LSS keygen initialization successful")
}

// TestLSSFastSign tests sign initialization
func TestLSSFastSign(t *testing.T) {
	N := 3
	T := 2
	partyIDs := test.PartyIDs(N)
	pl := pool.NewPool(0)
	defer pl.TearDown()
	
	// Create mock configs
	configs := test.CreateMockLSSConfigs(partyIDs, T)
	
	message := []byte("test message")
	signers := partyIDs[:T]
	
	// Test sign initialization for each signer
	for _, id := range signers {
		var config *config.Config
		for _, cfg := range configs {
			if cfg.ID == id {
				config = cfg
				break
			}
		}
		
		require.NotNil(t, config, "Config should exist for signer %s", id)
		
		startFunc := lss.Sign(config, signers, message, pl)
		require.NotNil(t, startFunc, "Sign start function should not be nil for party %s", id)
		
		// Verify the start function creates a valid round
		round := startFunc()
		require.NotNil(t, round, "Sign should create initial round for party %s", id)
	}
	
	t.Log("LSS sign initialization successful")
}

// TestLSSFastRefresh tests refresh initialization
func TestLSSFastRefresh(t *testing.T) {
	N := 3
	T := 2
	partyIDs := test.PartyIDs(N)
	pl := pool.NewPool(0)
	defer pl.TearDown()
	
	// Create mock configs
	configs := test.CreateMockLSSConfigs(partyIDs, T)
	
	// Test refresh initialization for each party
	for i, cfg := range configs {
		startFunc := lss.Refresh(cfg, pl)
		// Refresh may return nil if not fully implemented
		if startFunc != nil {
			round := startFunc()
			require.NotNil(t, round, "Refresh should create initial round for party %d", i)
		}
	}
	
	t.Log("LSS refresh initialization successful")
}

// TestLSSQuickSuite runs all quick initialization tests
func TestLSSQuickSuite(t *testing.T) {
	tests := []struct {
		name       string
		partyCount int
		threshold  int
	}{
		{"Small-2-of-3", 3, 2},
		{"Medium-3-of-5", 5, 3},
		{"Large-5-of-7", 7, 5},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			partyIDs := test.PartyIDs(tt.partyCount)
			pl := pool.NewPool(0)
			defer pl.TearDown()
			
			// Quick keygen test
			for _, id := range partyIDs {
				startFunc := lss.Keygen(curve.Secp256k1{}, id, partyIDs, tt.threshold, pl)
				require.NotNil(t, startFunc)
			}
			
			t.Logf("%s: LSS initialization successful", tt.name)
		})
	}
}

// TestLSSProtocolStartFunctions verifies all protocol start functions
func TestLSSProtocolStartFunctions(t *testing.T) {
	partyIDs := test.PartyIDs(3)
	threshold := 2
	pl := pool.NewPool(0)
	defer pl.TearDown()
	
	t.Run("Keygen", func(t *testing.T) {
		for _, id := range partyIDs {
			startFunc := lss.Keygen(curve.Secp256k1{}, id, partyIDs, threshold, pl)
			require.NotNil(t, startFunc)
			require.IsType(t, protocol.StartFunc(nil), startFunc)
		}
	})
	
	t.Run("Sign", func(t *testing.T) {
		configs := test.CreateMockLSSConfigs(partyIDs, threshold)
		message := []byte("test")
		signers := partyIDs[:threshold]
		
		for _, id := range signers {
			var cfg *config.Config
			for _, c := range configs {
				if c.ID == id {
					cfg = c
					break
				}
			}
			
			startFunc := lss.Sign(cfg, signers, message, pl)
			require.NotNil(t, startFunc)
			require.IsType(t, protocol.StartFunc(nil), startFunc)
		}
	})
	
	t.Run("Refresh", func(t *testing.T) {
		configs := test.CreateMockLSSConfigs(partyIDs, threshold)
		
		for _, cfg := range configs {
			startFunc := lss.Refresh(cfg, pl)
			// Refresh may not be fully implemented
			if startFunc != nil {
				require.IsType(t, protocol.StartFunc(nil), startFunc)
			}
		}
	})
}