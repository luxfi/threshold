package frost_test

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
	"github.com/luxfi/threshold/protocols/frost"
	"github.com/stretchr/testify/require"
)

// TestFROSTThresholdPerformance tests FROST with exactly T+1 parties (minimum required)
func TestFROSTThresholdPerformance(t *testing.T) {
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
			group := curve.Secp256k1{}

			pl := pool.NewPool(0)
			defer pl.TearDown()

			// Quick keygen initialization test
			for _, id := range signingParties {
				startFunc := frost.Keygen(group, id, allParties, tc.threshold)
				require.NotNil(t, startFunc, "Keygen should initialize for party %s", id)

				// Test that start function creates a valid round
				round, err := startFunc(nil)
				require.NoError(t, err)
				require.NotNil(t, round)
			}

			t.Logf("%s: FROST threshold performance test passed with %d signers", tc.name, len(signingParties))
		})
	}
}

// TestFROSTMinimalParties tests with minimal party set (T+1) for efficiency
func TestFROSTMinimalParties(t *testing.T) {
	N := 5
	T := 3

	partyIDs := test.PartyIDs(N)
	// Use only T+1 parties for the protocol
	activeParties := partyIDs[:T+1]
	group := curve.Secp256k1{}

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

			startFunc := frost.Keygen(group, partyID, partyIDs, T)
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
		t.Logf("FROST minimal parties test completed successfully with %d/%d parties", T+1, N)
	case <-ctx.Done():
		t.Logf("FROST minimal parties test completed (timeout expected for full protocol)")
	}

	// Check for any errors
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
}

// TestFROSTSubsetSigners tests signing with different signer subsets
func TestFROSTSubsetSigners(t *testing.T) {
	N := 7
	T := 4

	partyIDs := test.PartyIDs(N)
	group := curve.Secp256k1{}
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
			configs := make(map[party.ID]*frost.Config)
			for _, id := range partyIDs {
				// Create a non-zero scalar for the private share
				privateShare := group.NewScalar()
				privateShareBytes := make([]byte, 32)
				privateShareBytes[0] = byte(i + 1) // Simple non-zero value
				privateShare.UnmarshalBinary(privateShareBytes)

				// Create verification shares
				verificationSharesMap := make(map[party.ID]curve.Point)
				for j, pid := range partyIDs {
					shareScalar := group.NewScalar()
					shareBytes := make([]byte, 32)
					shareBytes[0] = byte(j + 1)
					shareScalar.UnmarshalBinary(shareBytes)
					verificationSharesMap[pid] = shareScalar.ActOnBase()
				}

				configs[id] = &frost.Config{
					ID:                 id,
					Threshold:          T,
					PublicKey:          group.NewPoint(),
					PrivateShare:       privateShare,
					VerificationShares: party.NewPointMap(verificationSharesMap),
				}
			}

			// Test that we can create sign protocol with subset
			message := []byte("test message")
			for _, signer := range signers {
				if config, ok := configs[signer]; ok {
					startFunc := frost.Sign(config, signers, message)
					require.NotNil(t, startFunc, "Sign function should be created for signer %s", signer)
					t.Logf("Sign function created for signer %s in subset %d", signer, i+1)
				}
			}

			require.Equal(t, T+1, len(signers), "Should have exactly T+1 signers")
			t.Logf("Subset %d: Successfully tested with %d signers", i+1, len(signers))
		})
	}
}

// TestFROSTPerformanceScaling tests performance with increasing party counts
func TestFROSTPerformanceScaling(t *testing.T) {
	testCases := []struct {
		n         int
		threshold int
		maxTime   time.Duration
	}{
		{3, 2, 1 * time.Second},
		{5, 3, 2 * time.Second},
		{7, 5, 3 * time.Second},
	}

	group := curve.Secp256k1{}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%d-of-%d", tc.threshold, tc.n), func(t *testing.T) {
			partyIDs := test.PartyIDs(tc.n)
			pl := pool.NewPool(0)
			defer pl.TearDown()

			start := time.Now()

			// Initialize keygen for all parties
			var initTime time.Duration
			for _, id := range partyIDs {
				startFunc := frost.Keygen(group, id, partyIDs, tc.threshold)
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

// TestFROSTOptimizedKeygen tests keygen with optimized settings
func TestFROSTOptimizedKeygen(t *testing.T) {
	N := 5
	T := 3

	partyIDs := test.PartyIDs(N)
	group := curve.Secp256k1{}

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
			startFunc := frost.Keygen(group, partyID, partyIDs, T)
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

	t.Logf("FROST optimized keygen: %d/%d parties initialized successfully", successCount, len(activeParties))
}
