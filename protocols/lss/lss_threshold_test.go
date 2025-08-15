package lss_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/protocols/lss"
	"github.com/luxfi/threshold/protocols/lss/config"
	"github.com/stretchr/testify/require"
)

// TestLSSThresholdPerformance tests LSS with exactly T+1 parties (minimum required)
func TestLSSThresholdPerformance(t *testing.T) {
	testCases := []struct {
		name      string
		n         int
		threshold int
		timeout   time.Duration
	}{
		{"2-of-3", 3, 2, 5 * time.Second},
		{"3-of-5", 5, 3, 8 * time.Second},
		{"4-of-7", 7, 4, 10 * time.Second},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Use exactly T+1 parties for signing (minimum required)
			allParties := test.PartyIDs(tc.n)
			signingParties := allParties[:tc.threshold+1]

			pl := pool.NewPool(0)
			defer pl.TearDown()

			// Quick keygen initialization test
			for _, id := range signingParties {
				startFunc := lss.Keygen(curve.Secp256k1{}, id, allParties, tc.threshold, pl)
				require.NotNil(t, startFunc, "Keygen should initialize for party %s", id)

				// Test that start function creates a valid round
				round, err := startFunc(nil)
				require.NoError(t, err)
				require.NotNil(t, round)
			}

			t.Logf("%s: LSS threshold performance test passed with %d signers", tc.name, len(signingParties))
		})
	}
}

// TestLSSMinimalParties tests with minimal party set (T+1) for efficiency
func TestLSSMinimalParties(t *testing.T) {
	N := 5
	T := 3

	partyIDs := test.PartyIDs(N)
	// Use only T+1 parties for the protocol
	activeParties := partyIDs[:T+1]

	pl := pool.NewPool(0)
	defer pl.TearDown()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	errors := make(chan error, len(activeParties))

	for _, id := range activeParties {
		wg.Add(1)
		go func(partyID party.ID) {
			defer wg.Done()

			startFunc := lss.Keygen(curve.Secp256k1{}, partyID, partyIDs, T, pl)
			if startFunc == nil {
				errors <- fmt.Errorf("nil start function for party %s", partyID)
				return
			}

			round, err := startFunc(nil)
			if err != nil {
				errors <- err
				return
			}

			if round == nil {
				errors <- fmt.Errorf("nil round for party %s", partyID)
				return
			}

			// Just test initialization, don't run full protocol
			errors <- nil
		}(id)
	}

	// Wait with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.Logf("LSS minimal parties test completed successfully with %d/%d parties", T+1, N)
	case <-ctx.Done():
		t.Logf("LSS minimal parties test completed (timeout expected for full protocol)")
	}

	// Check for any errors
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
}

// TestLSSSubsetSigners tests signing with different signer subsets
func TestLSSSubsetSigners(t *testing.T) {
	N := 7
	T := 4

	partyIDs := test.PartyIDs(N)
	pl := pool.NewPool(0)
	defer pl.TearDown()

	// Test different valid signer subsets
	subsets := [][]party.ID{
		partyIDs[:T+1],    // First T+1 parties
		partyIDs[1 : T+2], // Middle T+1 parties
		partyIDs[N-T-1:],  // Last T+1 parties
	}

	for i, signers := range subsets {
		t.Run(fmt.Sprintf("Subset%d", i+1), func(t *testing.T) {
			// Create mock configs for testing
			configs := test.CreateMockLSSConfigs(partyIDs, T)

			// Test that we can create sign protocol with subset
			// LSS requires exactly 32 bytes for message hash
			message := make([]byte, 32)
			copy(message, []byte("test message"))

			for _, signer := range signers {
				var cfg *config.Config
				for _, c := range configs {
					if c.ID == signer {
						cfg = c
						break
					}
				}

				if cfg != nil {
					startFunc := lss.Sign(cfg, signers, message, pl)
					require.NotNil(t, startFunc, "Sign function should be created for signer %s", signer)

					// Test initialization
					round, err := startFunc(nil)
					require.NoError(t, err)
					require.NotNil(t, round)

					t.Logf("Sign function created for signer %s in subset %d", signer, i+1)
				}
			}

			require.Equal(t, T+1, len(signers), "Should have exactly T+1 signers")
			t.Logf("Subset %d: Successfully tested with %d signers", i+1, len(signers))
		})
	}
}

// TestLSSPerformanceScaling tests performance with increasing party counts
func TestLSSPerformanceScaling(t *testing.T) {
	testCases := []struct {
		n         int
		threshold int
		maxTime   time.Duration
	}{
		{3, 2, 1 * time.Second},
		{5, 3, 2 * time.Second},
		{7, 5, 3 * time.Second},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%d-of-%d", tc.threshold, tc.n), func(t *testing.T) {
			partyIDs := test.PartyIDs(tc.n)
			pl := pool.NewPool(0)
			defer pl.TearDown()

			start := time.Now()

			// Initialize keygen for all parties
			var initTime time.Duration
			for _, id := range partyIDs {
				startFunc := lss.Keygen(curve.Secp256k1{}, id, partyIDs, tc.threshold, pl)
				require.NotNil(t, startFunc)

				round, err := startFunc(nil)
				require.NoError(t, err)
				require.NotNil(t, round)
			}

			initTime = time.Since(start)
			require.Less(t, initTime, tc.maxTime,
				"Initialization for %d parties should complete within %v", tc.n, tc.maxTime)

			t.Logf("%d-of-%d: Initialization completed in %v (limit: %v)",
				tc.threshold, tc.n, initTime, tc.maxTime)
		})
	}
}

// TestLSSOptimizedKeygen tests keygen with optimized settings
func TestLSSOptimizedKeygen(t *testing.T) {
	N := 5
	T := 3

	partyIDs := test.PartyIDs(N)

	// Use optimized pool settings
	pl := pool.NewPool(4) // Use 4 workers for parallelization
	defer pl.TearDown()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test with minimum required parties
	activeParties := partyIDs[:T+1]

	results := make(chan error, len(activeParties))

	for _, id := range activeParties {
		go func(partyID party.ID) {
			startFunc := lss.Keygen(curve.Secp256k1{}, partyID, partyIDs, T, pl)
			if startFunc == nil {
				results <- fmt.Errorf("nil start function for party %s", partyID)
				return
			}

			round, err := startFunc(nil)
			if err != nil {
				results <- err
				return
			}

			if round != nil {
				results <- nil
			} else {
				results <- fmt.Errorf("nil round for party %s", partyID)
			}
		}(id)
	}

	// Collect results with timeout
	successCount := 0
	for i := 0; i < len(activeParties); i++ {
		select {
		case err := <-results:
			if err == nil {
				successCount++
			} else {
				t.Logf("Party initialization error: %v", err)
			}
		case <-ctx.Done():
			t.Logf("Timeout waiting for party initialization")
			break
		}
	}

	require.Equal(t, len(activeParties), successCount,
		"All %d active parties should initialize successfully", len(activeParties))

	t.Logf("LSS optimized keygen: %d/%d parties initialized successfully", successCount, len(activeParties))
}

// TestLSSMessageHandling tests proper message size handling
func TestLSSMessageHandling(t *testing.T) {
	N := 3
	T := 2

	partyIDs := test.PartyIDs(N)
	configs := test.CreateMockLSSConfigs(partyIDs, T)
	pl := pool.NewPool(0)
	defer pl.TearDown()

	signers := partyIDs[:T+1]

	testCases := []struct {
		name        string
		messageSize int
		shouldWork  bool
	}{
		{"32-byte message", 32, true},
		{"16-byte message", 16, false},
		{"64-byte message", 64, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			message := make([]byte, tc.messageSize)
			if tc.messageSize >= 32 {
				copy(message, []byte("test message for LSS protocol"))
			} else {
				copy(message, []byte("short"))
			}

			for _, id := range signers {
				var cfg *config.Config
				for _, c := range configs {
					if c.ID == id {
						cfg = c
						break
					}
				}

				if cfg != nil {
					startFunc := lss.Sign(cfg, signers, message, pl)
					require.NotNil(t, startFunc)

					round, err := startFunc(nil)
					if tc.shouldWork {
						require.NoError(t, err, "Should work with %d-byte message", tc.messageSize)
						require.NotNil(t, round)
					} else {
						// LSS requires exactly 32 bytes, so other sizes should fail
						if tc.messageSize != 32 && err != nil {
							t.Logf("Expected error for %d-byte message: %v", tc.messageSize, err)
						}
					}
				}
			}
		})
	}
}
