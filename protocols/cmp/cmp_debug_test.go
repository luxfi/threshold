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

// TestCMPDebugKeygen tests keygen with detailed logging
func TestCMPDebugKeygen(t *testing.T) {
	N := 2
	T := 1
	partyIDs := test.PartyIDs(N)

	// Create separate pools
	pools := make(map[party.ID]*pool.Pool)
	for _, id := range partyIDs {
		pools[id] = pool.NewPool(0)
	}
	defer func() {
		for _, pl := range pools {
			pl.TearDown()
		}
	}()

	// Create network
	network := test.NewNetwork(partyIDs)
	defer network.Close()

	// Run protocol for each party
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	configs := make(map[party.ID]*cmp.Config)
	errors := make(map[party.ID]error)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, id := range partyIDs {
		wg.Add(1)
		go func(id party.ID) {
			defer wg.Done()

			logger := log.NewTestLogger(level.Debug)
			sessionID := []byte("debug-keygen")
			protocolConfig := protocol.DefaultConfig()

			// Create handler
			h, err := protocol.NewHandler(ctx, logger, prometheus.NewRegistry(),
				cmp.Keygen(curve.Secp256k1{}, id, partyIDs, T, pools[id]),
				sessionID, protocolConfig)

			if err != nil {
				mu.Lock()
				errors[id] = err
				mu.Unlock()
				t.Logf("Party %s: handler creation failed: %v", id, err)
				return
			}

			// Run handler
			done := make(chan struct{})
			go func() {
				defer close(done)
				test.HandlerLoop(id, h, network)
			}()

			// Wait for completion
			select {
			case <-done:
				result, err := h.Result()
				mu.Lock()
				if err != nil {
					errors[id] = err
					t.Logf("Party %s: protocol failed: %v", id, err)
				} else if cfg, ok := result.(*cmp.Config); ok {
					configs[id] = cfg
					t.Logf("Party %s: protocol succeeded", id)
				}
				mu.Unlock()
			case <-ctx.Done():
				mu.Lock()
				errors[id] = ctx.Err()
				mu.Unlock()
				t.Logf("Party %s: timed out", id)
			}
		}(id)
	}

	wg.Wait()

	// Check results
	t.Logf("Results: %d configs, %d errors", len(configs), len(errors))

	for id, err := range errors {
		t.Logf("Party %s error: %v", id, err)
	}

	if len(configs) == N {
		// Verify public keys match
		var firstPubKey curve.Point
		for id, cfg := range configs {
			pubKey := cfg.PublicPoint()
			if firstPubKey == nil {
				firstPubKey = pubKey
			} else {
				require.True(t, firstPubKey.Equal(pubKey),
					"Party %s has different public key", id)
			}
		}
		t.Log("SUCCESS: All parties completed with matching public keys")
	}
}

// TestCMPIsolatedRounds tests individual rounds
func TestCMPIsolatedRounds(t *testing.T) {
	N := 2
	T := 1
	partyIDs := test.PartyIDs(N)

	pl := pool.NewPool(0)
	defer pl.TearDown()

	// Test that we can create the keygen function
	for _, id := range partyIDs {
		startFunc := cmp.Keygen(curve.Secp256k1{}, id, partyIDs, T, pl)
		require.NotNil(t, startFunc, "Keygen should return start function")

		// Test round initialization
		round1, err := startFunc([]byte("test-session"))
		if err != nil {
			t.Logf("Party %s: Round 1 init error: %v", id, err)
		} else {
			require.NotNil(t, round1, "Round 1 should be created")
			t.Logf("Party %s: Round 1 initialized successfully", id)
		}
	}
}
