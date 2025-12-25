package lss_test

import (
	"crypto/sha256"
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
	"github.com/luxfi/threshold/protocols/lss/sign"
	"github.com/stretchr/testify/require"
)

// TestLSSKeygenThenSign is a complete end-to-end test:
// 1. Run keygen for all parties
// 2. Use threshold-sized subset to sign a message
// 3. Verify the signature
func TestLSSKeygenThenSign(t *testing.T) {
	n := 5
	threshold := 3
	partyIDs := test.PartyIDs(n)
	group := curve.Secp256k1{}
	// Message hash must be 32 bytes (SHA256 of actual message)
	msgHash := sha256.Sum256([]byte("test message for LSS signing"))
	message := msgHash[:]
	pl := pool.NewPool(0)
	defer pl.TearDown()

	t.Log("Starting LSS keygen + sign integration test")
	t.Logf("Parties: %d, Threshold: %d", n, threshold)

	// Step 1: Run keygen
	t.Log("Step 1: Running LSS keygen...")
	harness := test.NewHarness(t, partyIDs).WithTimeout(60 * time.Second)
	defer harness.Cleanup()

	sessionID := []byte(fmt.Sprintf("lss-keygen-sign-test-%d", time.Now().UnixNano()))

	for _, id := range partyIDs {
		_, err := harness.CreateHandler(id, lss.Keygen(group, id, partyIDs, threshold, pl), sessionID)
		require.NoError(t, err, "Failed to create keygen handler for party %s", id)
	}

	err := harness.Run()
	require.NoError(t, err, "Keygen failed")

	// Extract configs
	configs := make(map[party.ID]*config.Config)
	for _, id := range partyIDs {
		result, err := harness.Result(id)
		require.NoError(t, err, "Failed to get keygen result for party %s", id)
		cfg, ok := result.(*config.Config)
		require.True(t, ok, "Result is not a config for party %s", id)
		require.NotNil(t, cfg, "Config is nil for party %s", id)
		require.NotNil(t, cfg.ECDSA, "ECDSA share is nil for party %s", id)
		configs[id] = cfg
		t.Logf("Party %s: got valid config with ECDSA share", id)
	}

	// Verify all parties have same public key
	var publicKey curve.Point
	for id, cfg := range configs {
		pk, err := cfg.PublicPoint()
		require.NoError(t, err, "Failed to get public key for party %s", id)
		if publicKey == nil {
			publicKey = pk
		} else {
			require.True(t, publicKey.Equal(pk), "Public keys don't match for party %s", id)
		}
	}
	t.Logf("All parties have matching public key")

	// Step 2: Run sign with threshold parties
	t.Log("Step 2: Running LSS sign...")
	signers := partyIDs[:threshold]
	t.Logf("Signers: %v", signers)

	signHarness := test.NewHarness(t, signers).WithTimeout(60 * time.Second)
	defer signHarness.Cleanup()

	signSessionID := []byte(fmt.Sprintf("lss-sign-test-%d", time.Now().UnixNano()))

	for _, id := range signers {
		cfg := configs[id]
		require.NotNil(t, cfg, "Config is nil for signer %s", id)
		_, err := signHarness.CreateHandler(id, lss.Sign(cfg, signers, message, pl), signSessionID)
		require.NoError(t, err, "Failed to create sign handler for party %s", id)
	}

	err = signHarness.Run()
	require.NoError(t, err, "Sign protocol failed")

	// Step 3: Verify signatures
	t.Log("Step 3: Verifying signatures...")
	for _, id := range signers {
		result, err := signHarness.Result(id)
		require.NoError(t, err, "Failed to get sign result for party %s", id)
		require.NotNil(t, result, "Sign result is nil for party %s", id)

		sig, ok := result.(*sign.SchnorrSignature)
		require.True(t, ok, "Result is not a SchnorrSignature for party %s", id)
		require.NotNil(t, sig, "Signature is nil for party %s", id)
		require.NotNil(t, sig.R, "Signature R is nil for party %s", id)
		require.NotNil(t, sig.Z, "Signature Z is nil for party %s", id)

		// Verify the signature
		valid := sig.Verify(publicKey, message)
		require.True(t, valid, "Signature verification failed for party %s", id)
		t.Logf("Party %s: signature verified successfully", id)
	}

	t.Log("LSS keygen + sign integration test PASSED!")
}

// TestLSSSignMultipleSubsets tests signing with different signer subsets
func TestLSSSignMultipleSubsets(t *testing.T) {
	n := 5
	threshold := 3
	partyIDs := test.PartyIDs(n)
	group := curve.Secp256k1{}
	pl := pool.NewPool(0)
	defer pl.TearDown()

	// First run keygen
	harness := test.NewHarness(t, partyIDs).WithTimeout(60 * time.Second)
	defer harness.Cleanup()

	sessionID := []byte(fmt.Sprintf("lss-subset-keygen-%d", time.Now().UnixNano()))

	for _, id := range partyIDs {
		_, err := harness.CreateHandler(id, lss.Keygen(group, id, partyIDs, threshold, pl), sessionID)
		require.NoError(t, err)
	}

	err := harness.Run()
	require.NoError(t, err, "Keygen failed")

	// Extract configs
	configs := make(map[party.ID]*config.Config)
	var publicKey curve.Point
	for _, id := range partyIDs {
		result, err := harness.Result(id)
		require.NoError(t, err)
		cfg := result.(*config.Config)
		configs[id] = cfg
		if publicKey == nil {
			publicKey, _ = cfg.PublicPoint()
		}
	}

	// Test different signer subsets
	subsets := [][]party.ID{
		partyIDs[:threshold],                         // First 3
		partyIDs[len(partyIDs)-threshold:],           // Last 3
		{partyIDs[0], partyIDs[2], partyIDs[4]},      // Every other
	}

	for i, signers := range subsets {
		t.Run(fmt.Sprintf("Subset%d", i+1), func(t *testing.T) {
			msgHash := sha256.Sum256([]byte(fmt.Sprintf("message for subset %d", i+1)))
			message := msgHash[:]

			signHarness := test.NewHarness(t, signers).WithTimeout(60 * time.Second)
			defer signHarness.Cleanup()

			signSessionID := []byte(fmt.Sprintf("lss-subset-sign-%d-%d", i, time.Now().UnixNano()))

			for _, id := range signers {
				cfg := configs[id]
				_, err := signHarness.CreateHandler(id, lss.Sign(cfg, signers, message, pl), signSessionID)
				require.NoError(t, err)
			}

			err := signHarness.Run()
			require.NoError(t, err, "Sign failed for subset %d", i+1)

			// Verify signature
			result, err := signHarness.Result(signers[0])
			require.NoError(t, err)
			sig := result.(*sign.SchnorrSignature)
			require.True(t, sig.Verify(publicKey, message), "Signature verification failed for subset %d", i+1)
			t.Logf("Subset %d: signature verified", i+1)
		})
	}
}

// TestLSSSignConcurrent tests concurrent signing sessions
func TestLSSSignConcurrent(t *testing.T) {
	n := 3
	threshold := 2
	partyIDs := test.PartyIDs(n)
	group := curve.Secp256k1{}
	pl := pool.NewPool(0)
	defer pl.TearDown()

	// Run keygen
	harness := test.NewHarness(t, partyIDs).WithTimeout(60 * time.Second)
	defer harness.Cleanup()

	sessionID := []byte(fmt.Sprintf("lss-concurrent-keygen-%d", time.Now().UnixNano()))

	for _, id := range partyIDs {
		_, err := harness.CreateHandler(id, lss.Keygen(group, id, partyIDs, threshold, pl), sessionID)
		require.NoError(t, err)
	}

	err := harness.Run()
	require.NoError(t, err, "Keygen failed")

	// Extract configs
	configs := make(map[party.ID]*config.Config)
	var publicKey curve.Point
	for _, id := range partyIDs {
		result, err := harness.Result(id)
		require.NoError(t, err)
		cfg := result.(*config.Config)
		configs[id] = cfg
		if publicKey == nil {
			publicKey, _ = cfg.PublicPoint()
		}
	}

	// Run 3 concurrent signing sessions
	numSessions := 3
	signers := partyIDs[:threshold]

	var wg sync.WaitGroup
	results := make(chan error, numSessions)

	for i := 0; i < numSessions; i++ {
		wg.Add(1)
		go func(sessionNum int) {
			defer wg.Done()

			msgHash := sha256.Sum256([]byte(fmt.Sprintf("concurrent message %d", sessionNum)))
			message := msgHash[:]

			signHarness := test.NewHarness(t, signers).WithTimeout(60 * time.Second)
			defer signHarness.Cleanup()

			signSessionID := []byte(fmt.Sprintf("lss-concurrent-sign-%d-%d", sessionNum, time.Now().UnixNano()))

			for _, id := range signers {
				cfg := configs[id]
				_, err := signHarness.CreateHandler(id, lss.Sign(cfg, signers, message, pl), signSessionID)
				if err != nil {
					results <- fmt.Errorf("session %d: failed to create handler: %w", sessionNum, err)
					return
				}
			}

			err := signHarness.Run()
			if err != nil {
				results <- fmt.Errorf("session %d: sign failed: %w", sessionNum, err)
				return
			}

			// Verify
			result, err := signHarness.Result(signers[0])
			if err != nil {
				results <- fmt.Errorf("session %d: failed to get result: %w", sessionNum, err)
				return
			}

			sig := result.(*sign.SchnorrSignature)
			if !sig.Verify(publicKey, message) {
				results <- fmt.Errorf("session %d: signature verification failed", sessionNum)
				return
			}

			t.Logf("Session %d: signature verified", sessionNum)
			results <- nil
		}(i)
	}

	wg.Wait()
	close(results)

	for err := range results {
		require.NoError(t, err)
	}

	t.Log("All concurrent signing sessions completed successfully")
}
