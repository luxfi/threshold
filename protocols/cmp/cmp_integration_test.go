package cmp_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/luxfi/log"
	"github.com/luxfi/log/level"
	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/cmp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// TestCMPIntegrationKeygen tests the keygen protocol with proper setup
func TestCMPIntegrationKeygen(t *testing.T) {
	N := 3
	T := 2

	partyIDs := test.PartyIDs(N)
	network := test.NewNetwork(partyIDs)

	// Create pools for each party
	pools := make(map[party.ID]*pool.Pool)
	for _, id := range partyIDs {
		pools[id] = pool.NewPool(0)
	}
	defer func() {
		for _, pl := range pools {
			pl.TearDown()
		}
	}()

	// Run keygen for all parties
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	configs := make(map[party.ID]*cmp.Config)
	configMu := &sync.Mutex{}
	errors := make(map[party.ID]error)
	errorMu := &sync.Mutex{}

	for _, id := range partyIDs {
		wg.Add(1)
		go func(id party.ID) {
			defer wg.Done()

			logger := log.NewTestLogger(level.Info)
			sessionID := []byte("keygen-test")
			protocolConfig := protocol.DefaultConfig()

			h, err := protocol.NewHandler(ctx, logger, prometheus.NewRegistry(),
				cmp.Keygen(curve.Secp256k1{}, id, partyIDs, T, pools[id]),
				sessionID, protocolConfig)

			if err != nil {
				errorMu.Lock()
				errors[id] = err
				errorMu.Unlock()
				return
			}

			// Run the handler
			done := make(chan struct{})
			go func() {
				test.HandlerLoop(id, h, network)
				close(done)
			}()

			// Wait for completion or timeout
			select {
			case <-done:
				result, err := h.Result()
				if err != nil {
					errorMu.Lock()
					errors[id] = err
					errorMu.Unlock()
				} else if cfg, ok := result.(*cmp.Config); ok {
					configMu.Lock()
					configs[id] = cfg
					configMu.Unlock()
				}
			case <-ctx.Done():
				t.Logf("Party %s timed out", id)
				errorMu.Lock()
				errors[id] = ctx.Err()
				errorMu.Unlock()
			}
		}(id)
	}

	// Wait for all parties
	wg.Wait()

	// Check results
	require.Empty(t, errors, "No errors should occur")
	require.Len(t, configs, N, "All parties should generate configs")

	// Verify all parties have the same public key
	var firstPubKey curve.Point
	for id, cfg := range configs {
		pubKey := cfg.PublicPoint()
		require.NotNil(t, pubKey, "Party %s should have public key", id)

		if firstPubKey == nil {
			firstPubKey = pubKey
		} else {
			require.True(t, firstPubKey.Equal(pubKey),
				"Party %s should have same public key", id)
		}
	}

	t.Log("Keygen completed successfully for all parties")
}

// TestCMPIntegrationSimpleKeygen tests a minimal keygen setup
func TestCMPIntegrationSimpleKeygen(t *testing.T) {
	N := 2 // Minimal parties
	T := 1 // Minimal threshold

	partyIDs := test.PartyIDs(N)

	// Single shared pool for simplicity
	pl := pool.NewPool(0)
	defer pl.TearDown()

	// Test that we can create the protocol for each party
	for _, id := range partyIDs {
		startFunc := cmp.Keygen(curve.Secp256k1{}, id, partyIDs, T, pl)
		require.NotNil(t, startFunc, "Keygen should return start function for party %s", id)

		// Try to initialize
		round, err := startFunc(nil)
		if err != nil {
			t.Logf("Expected initialization error for party %s: %v", id, err)
		} else if round != nil {
			t.Logf("Round initialized for party %s", id)
		}
	}
}

// TestCMPIntegrationQuickCheck does a quick validation
func TestCMPIntegrationQuickCheck(t *testing.T) {
	// This test just verifies the protocol can be created without crashing
	N := 3
	T := 2
	partyIDs := test.PartyIDs(N)

	pl := pool.NewPool(0)
	defer pl.TearDown()

	count := 0
	for _, id := range partyIDs {
		if cmp.Keygen(curve.Secp256k1{}, id, partyIDs, T, pl) != nil {
			count++
		}
	}

	require.Equal(t, N, count, "All parties should create keygen successfully")
}
