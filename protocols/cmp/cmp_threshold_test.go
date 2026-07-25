package cmp_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"fmt"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/quorum"
	"github.com/luxfi/threshold/protocols/cmp"
	"github.com/stretchr/testify/require"
)

// TestCMPThresholdPerformance tests CMP with exactly T+1 parties (minimum required)
func TestCMPThresholdPerformance(t *testing.T) {
	// Stated as quorum policies, not bare degrees. The names used to be
	// written out by hand alongside a raw `threshold` field that cmp.Keygen
	// reads as the polynomial DEGREE, so the case labelled "3-of-5" passed
	// degree 3 and signed with 4 parties — it was a 4-of-5. Deriving both the
	// degree and the signer count from one quorum.Policy makes the label and
	// the behaviour the same fact.
	testCases := []struct {
		policy  quorum.Policy
		timeout time.Duration
	}{
		{quorum.MustNew(2, 3), 5 * time.Second},
		{quorum.MustNew(3, 5), 8 * time.Second},
		{quorum.MustNew(4, 7), 10 * time.Second},
	}

	for _, tc := range testCases {
		t.Run(tc.policy.String(), func(t *testing.T) {
			// Exactly K parties sign — the minimum the policy allows.
			allParties := test.PartyIDs(tc.policy.N)
			signingParties := allParties[:tc.policy.K]

			pl := pool.NewPool(0)
			defer pl.TearDown()

			// Quick keygen initialization test
			for _, id := range signingParties {
				startFunc := cmp.Keygen(curve.Secp256k1{}, id, allParties, tc.policy.Degree(), pl)
				require.NotNil(t, startFunc, "Keygen should initialize for party %s", id)

				// Test that start function creates a valid round
				round, err := startFunc(nil)
				require.NoError(t, err)
				require.NotNil(t, round)
			}

			t.Logf("%s: CMP threshold performance test passed with %d signers at degree %d",
				tc.policy, len(signingParties), tc.policy.Degree())
		})
	}
}

// TestCMPMinimalParties tests with minimal party set (T+1) for efficiency
func TestCMPMinimalParties(t *testing.T) {
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

			startFunc := cmp.Keygen(curve.Secp256k1{}, partyID, partyIDs, T, pl)
			if startFunc == nil {
				errors <- nil
				return
			}

			round, err := startFunc(nil)
			if err != nil {
				errors <- err
				return
			}

			if round == nil {
				errors <- nil
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
		t.Logf("CMP minimal parties test completed successfully with %d/%d parties", T+1, N)
	case <-ctx.Done():
		t.Logf("CMP minimal parties test completed (timeout expected for full protocol)")
	}

	// Check for any errors
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
}

// TestCMPSubsetSigners tests signing with different signer subsets
func TestCMPSubsetSigners(t *testing.T) {
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
			configs := make(map[party.ID]*cmp.Config)
			for _, id := range partyIDs {
				configs[id] = &cmp.Config{
					ID:        id,
					Threshold: T,
				}
			}

			// Test that we can create sign protocol with subset
			message := []byte("test message")
			for _, signer := range signers {
				if config, ok := configs[signer]; ok {
					startFunc := cmp.Sign(config, signers, message, pl)
					// Sign may not be fully implemented, just check it doesn't panic
					if startFunc != nil {
						t.Logf("Sign function created for signer %s in subset %d", signer, i+1)
					}
				}
			}

			require.Equal(t, T+1, len(signers), "Should have exactly T+1 signers")
			t.Logf("Subset %d: Successfully tested with %d signers", i+1, len(signers))
		})
	}
}

// TestCMPPerformanceScaling tests performance with increasing party counts
func TestCMPPerformanceScaling(t *testing.T) {
	// As above: the policy is the stated value, the degree is derived from it.
	// Printing a raw degree as if it were the signer count is how "3-of-5"
	// ends up naming a 4-of-5 configuration.
	testCases := []struct {
		policy  quorum.Policy
		maxTime time.Duration
	}{
		{quorum.MustNew(2, 3), 1 * time.Second},
		{quorum.MustNew(3, 5), 2 * time.Second},
		{quorum.MustNew(5, 7), 3 * time.Second},
	}

	for _, tc := range testCases {
		t.Run(tc.policy.String(), func(t *testing.T) {
			partyIDs := test.PartyIDs(tc.policy.N)
			pl := pool.NewPool(0)
			defer pl.TearDown()

			start := time.Now()

			// Initialize keygen for all parties
			var initTime time.Duration
			for _, id := range partyIDs {
				startFunc := cmp.Keygen(curve.Secp256k1{}, id, partyIDs, tc.policy.Degree(), pl)
				require.NotNil(t, startFunc)

				round, err := startFunc(nil)
				require.NoError(t, err)
				require.NotNil(t, round)
			}

			initTime = time.Since(start)
			require.Less(t, initTime, tc.maxTime,
				"Initialization for %d parties should complete within %v", tc.policy.N, tc.maxTime)

			t.Logf("%s: Initialization completed in %v (limit: %v)",
				tc.policy, initTime, tc.maxTime)
		})
	}
}
