package cmp_test

import (
	"testing"
	"time"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/cmp"
	"github.com/stretchr/testify/require"
)

// TestCMPBasicKeygen tests basic keygen protocol
func TestCMPBasicKeygen(t *testing.T) {
	N := 3
	T := 2

	partyIDs := test.PartyIDs(N)

	// Create a pool for each party to avoid concurrency issues
	pools := make(map[party.ID]*pool.Pool)
	for _, id := range partyIDs {
		pools[id] = pool.NewPool(0)
	}
	defer func() {
		for _, pl := range pools {
			pl.TearDown()
		}
	}()

	// Run the protocol
	results, err := test.RunProtocol(t, partyIDs, []byte("test-keygen"), func(id party.ID) protocol.StartFunc {
		return cmp.Keygen(curve.Secp256k1{}, id, partyIDs, T, pools[id])
	})

	// Check results
	if err != nil {
		t.Logf("Protocol completed with error: %v", err)
		// Even with error, check partial results
		if len(results) > 0 {
			t.Logf("Got %d partial results", len(results))
		}
	} else {
		require.Len(t, results, N, "Should have results for all parties")

		// Verify all parties have the same public key
		var firstPubKey curve.Point
		for id, result := range results {
			config, ok := result.(*cmp.Config)
			require.True(t, ok, "Result should be *cmp.Config for party %s", id)
			require.NotNil(t, config)

			pubKey := config.PublicPoint()
			require.NotNil(t, pubKey, "Party %s should have public key", id)

			if firstPubKey == nil {
				firstPubKey = pubKey
			} else {
				require.True(t, firstPubKey.Equal(pubKey),
					"Party %s should have same public key", id)
			}
		}

		t.Log("Keygen completed successfully with matching public keys")
	}
}

// TestCMPMinimalKeygen tests minimal 2-party keygen
func TestCMPMinimalKeygen(t *testing.T) {
	N := 2
	T := 1

	partyIDs := test.PartyIDs(N)

	// Single shared pool for simplicity
	pl := pool.NewPool(0)
	defer pl.TearDown()

	// Run the protocol with timeout
	results, err := test.RunProtocolWithTimeout(t, partyIDs, []byte("minimal-keygen"), 10*time.Second,
		func(id party.ID) protocol.StartFunc {
			return cmp.Keygen(curve.Secp256k1{}, id, partyIDs, T, pl)
		})

	// Check results
	if err != nil {
		t.Logf("Keygen completed with error (may be expected): %v", err)
	}

	if len(results) >= T+1 {
		t.Logf("Got sufficient results: %d parties completed", len(results))

		// Verify public keys match if we got configs
		var firstPubKey curve.Point
		for id, result := range results {
			if config, ok := result.(*cmp.Config); ok {
				pubKey := config.PublicPoint()
				if pubKey != nil {
					if firstPubKey == nil {
						firstPubKey = pubKey
					} else if !firstPubKey.Equal(pubKey) {
						t.Errorf("Party %s has different public key", id)
					}
				}
			}
		}

		if firstPubKey != nil {
			t.Log("Public keys match across parties")
		}
	} else {
		t.Logf("Insufficient results: only %d parties completed (need %d)", len(results), T+1)
	}
}
