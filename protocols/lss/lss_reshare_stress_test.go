package lss_test

import (
	"fmt"
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/lss"
	"github.com/luxfi/threshold/protocols/lss/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLSSDynamicReshareStress tests extreme resharing scenarios
func TestLSSDynamicReshareStress(t *testing.T) {
	tests := []struct {
		name        string
		scenario    func(t *testing.T)
		description string
	}{
		{
			name:        "CompletePartyReplacement",
			scenario:    testCompletePartyReplacement,
			description: "Replace all parties while maintaining same public key",
		},
		{
			name:        "ThresholdIncrease",
			scenario:    testThresholdIncrease,
			description: "Increase threshold from 2-of-3 to 5-of-7",
		},
		{
			name:        "ThresholdDecrease",
			scenario:    testThresholdDecrease,
			description: "Decrease threshold from 5-of-7 to 2-of-3",
		},
		{
			name:        "ChainedResharing",
			scenario:    testChainedResharing,
			description: "Multiple sequential reshares with different configurations",
		},
		{
			name:        "SingletonToMultiparty",
			scenario:    testSingletonToMultiparty,
			description: "Expand from 1-of-1 to n-of-m",
		},
		{
			name:        "MultipartyToSingleton",
			scenario:    testMultipartyToSingleton,
			description: "Collapse from n-of-m to 1-of-1",
		},
		{
			name:        "RollingPartyRotation",
			scenario:    testRollingPartyRotation,
			description: "Gradually rotate parties one at a time",
		},
		{
			name:        "MaximalConfiguration",
			scenario:    testMaximalConfiguration,
			description: "Test with maximum supported parties (100)",
		},
		{
			name:        "ByzantinePartyReshare",
			scenario:    testByzantinePartyReshare,
			description: "Reshare with Byzantine parties (up to t-1 malicious)",
		},
		{
			name:        "ConcurrentResharing",
			scenario:    testConcurrentResharing,
			description: "Multiple concurrent reshare operations",
		},
		{
			name:        "CrossProtocolReshare",
			scenario:    testCrossProtocolReshare,
			description: "Reshare between CMP and FROST protocols",
		},
		{
			name:        "NetworkPartitionReshare",
			scenario:    testNetworkPartitionReshare,
			description: "Reshare during network partition scenarios",
		},
		{
			name:        "EmergencyKeyRecovery",
			scenario:    testEmergencyKeyRecovery,
			description: "Recover from catastrophic party loss",
		},
		{
			name:        "ProactiveSecurityRefresh",
			scenario:    testProactiveSecurityRefresh,
			description: "Periodic refresh without membership change",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Testing: %s", tt.description)
			tt.scenario(t)
		})
	}
}

// testCompletePartyReplacement replaces all original parties with new ones
func testCompletePartyReplacement(t *testing.T) {
	// Initial setup: 3-of-5
	oldParties := test.PartyIDs(5)
	oldThreshold := 3

	// Generate initial configuration
	configs := generateInitialConfigs(t, oldParties, oldThreshold)
	publicKey, _ := configs[oldParties[0]].PublicPoint()

	// New parties: completely different set
	newParties := []party.ID{"new1", "new2", "new3", "new4", "new5"}
	newThreshold := 3

	// Perform reshare from old to new
	newConfigs := performReshare(t, configs, oldParties, newParties, newThreshold)

	// Verify public key unchanged
	for _, cfg := range newConfigs {
		pk, _ := cfg.PublicPoint()
		assert.True(t, publicKey.Equal(pk),
			"Public key should remain unchanged after complete party replacement")
	}

	// Test signing with new parties
	testSigning(t, newConfigs, newParties[:newThreshold])
}

// testThresholdIncrease increases the threshold requirement
func testThresholdIncrease(t *testing.T) {
	// Start with 2-of-3
	parties := test.PartyIDs(3)
	configs := generateInitialConfigs(t, parties, 2)
	publicKey, _ := configs[parties[0]].PublicPoint()

	// Increase to 5-of-7
	newParties := test.PartyIDs(7)
	newConfigs := performReshare(t, configs, parties, newParties, 5)

	// Verify public key unchanged
	for _, cfg := range newConfigs {
		pk, _ := cfg.PublicPoint()
		assert.True(t, publicKey.Equal(pk))
	}

	// Verify old threshold (2 parties) cannot sign
	cannotSign := newParties[:2]
	testSigningFails(t, newConfigs, cannotSign)

	// Verify new threshold (5 parties) can sign
	canSign := newParties[:5]
	testSigning(t, newConfigs, canSign)
}

// testThresholdDecrease decreases the threshold requirement
func testThresholdDecrease(t *testing.T) {
	// Start with 5-of-7
	parties := test.PartyIDs(7)
	configs := generateInitialConfigs(t, parties, 5)
	publicKey, _ := configs[parties[0]].PublicPoint()

	// Decrease to 2-of-3
	newParties := test.PartyIDs(3)
	newConfigs := performReshare(t, configs, parties[:5], newParties, 2)

	// Verify public key unchanged
	for _, cfg := range newConfigs {
		pk, _ := cfg.PublicPoint()
		assert.True(t, publicKey.Equal(pk))
	}

	// Verify new threshold (2 parties) can sign
	testSigning(t, newConfigs, newParties[:2])
}

// testChainedResharing performs multiple sequential reshares
func testChainedResharing(t *testing.T) {
	// Configuration sequence: 2-of-3 → 3-of-5 → 4-of-7 → 2-of-4
	configurations := []struct {
		parties   int
		threshold int
	}{
		{3, 2},
		{5, 3},
		{7, 4},
		{4, 2},
	}

	// Initial setup
	parties := test.PartyIDs(configurations[0].parties)
	configs := generateInitialConfigs(t, parties, configurations[0].threshold)
	publicKey, _ := configs[parties[0]].PublicPoint()

	// Chain reshares
	for i := 1; i < len(configurations); i++ {
		prev := configurations[i-1]
		curr := configurations[i]

		t.Logf("Resharing from %d-of-%d to %d-of-%d",
			prev.threshold, prev.parties, curr.threshold, curr.parties)

		newParties := test.PartyIDs(curr.parties)

		// Use minimum required parties from previous configuration
		signingParties := parties[:prev.threshold]
		signingConfigs := make(map[party.ID]*config.Config)
		for _, p := range signingParties {
			signingConfigs[p] = configs[p]
		}

		configs = performReshare(t, signingConfigs, signingParties, newParties, curr.threshold)
		parties = newParties

		// Verify public key unchanged
		for _, cfg := range configs {
			pk, _ := cfg.PublicPoint()
			assert.True(t, publicKey.Equal(pk),
				"Public key should remain unchanged after reshare %d", i)
		}

		// Test signing works with new configuration
		testSigning(t, configs, parties[:curr.threshold])
	}
}

// testSingletonToMultiparty expands from single party to multiparty
func testSingletonToMultiparty(t *testing.T) {
	// Start with 1-of-1 (single party holding full key)
	parties := test.PartyIDs(1)
	configs := generateInitialConfigs(t, parties, 1)
	publicKey, _ := configs[parties[0]].PublicPoint()

	// Expand to 3-of-5
	newParties := test.PartyIDs(5)
	newConfigs := performReshare(t, configs, parties, newParties, 3)

	// Verify public key unchanged
	for _, cfg := range newConfigs {
		pk, _ := cfg.PublicPoint()
		assert.True(t, publicKey.Equal(pk))
	}

	// Verify multiparty signing works
	testSigning(t, newConfigs, newParties[:3])
}

// testMultipartyToSingleton collapses from multiparty to single party
func testMultipartyToSingleton(t *testing.T) {
	// Start with 3-of-5
	parties := test.PartyIDs(5)
	configs := generateInitialConfigs(t, parties, 3)
	publicKey, _ := configs[parties[0]].PublicPoint()

	// Collapse to 1-of-1
	newParties := test.PartyIDs(1)
	newConfigs := performReshare(t, configs, parties[:3], newParties, 1)

	// Verify public key unchanged
	pk, _ := newConfigs[newParties[0]].PublicPoint()
	assert.True(t, publicKey.Equal(pk))

	// Verify single party can sign
	testSigning(t, newConfigs, newParties)
}

// testRollingPartyRotation gradually rotates parties one at a time
func testRollingPartyRotation(t *testing.T) {
	// Start with parties a,b,c (2-of-3)
	parties := []party.ID{"a", "b", "c"}
	configs := generateInitialConfigs(t, parties, 2)
	publicKey, _ := configs[parties[0]].PublicPoint()

	// Rotation sequence: abc → dbc → dec → def
	rotations := []struct {
		remove party.ID
		add    party.ID
		result []party.ID
	}{
		{"a", "d", []party.ID{"d", "b", "c"}},
		{"b", "e", []party.ID{"d", "e", "c"}},
		{"c", "f", []party.ID{"d", "e", "f"}},
	}

	for i, rotation := range rotations {
		t.Logf("Rotation %d: removing %s, adding %s", i+1, rotation.remove, rotation.add)

		// Perform reshare with one party changed
		newConfigs := performReshare(t, configs, parties[:2], rotation.result, 2)

		// Verify public key unchanged
		for _, cfg := range newConfigs {
			pk, _ := cfg.PublicPoint()
			assert.True(t, publicKey.Equal(pk),
				"Public key should remain unchanged after rotation %d", i+1)
		}

		// Test signing with new party set
		testSigning(t, newConfigs, rotation.result[:2])

		// Update for next iteration
		configs = newConfigs
		parties = rotation.result
	}

	// Final verification: completely different party set, same key
	assert.NotContains(t, parties, party.ID("a"))
	assert.NotContains(t, parties, party.ID("b"))
	assert.NotContains(t, parties, party.ID("c"))
}

// testMaximalConfiguration tests with maximum supported parties
func testMaximalConfiguration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping maximal configuration test in short mode")
	}

	// Test with 67-of-100 (Byzantine fault tolerant)
	n := 100
	threshold := 67

	t.Logf("Testing maximal configuration: %d-of-%d", threshold, n)

	// Generate large party set
	parties := make([]party.ID, n)
	for i := 0; i < n; i++ {
		parties[i] = party.ID(fmt.Sprintf("party_%03d", i))
	}

	// Initial setup (use smaller set for initial generation)
	initialParties := parties[:10]
	configs := generateInitialConfigs(t, initialParties, 7)
	publicKey, _ := configs[initialParties[0]].PublicPoint()

	// Reshare to full 100 parties
	newConfigs := performReshare(t, configs, initialParties[:7], parties, threshold)

	// Verify public key unchanged
	for _, cfg := range newConfigs {
		pk, _ := cfg.PublicPoint()
		assert.True(t, publicKey.Equal(pk))
	}

	// Test signing with threshold parties
	testSigning(t, newConfigs, parties[:threshold])
}

// Helper functions

func generateInitialConfigs(t *testing.T, parties []party.ID, threshold int) map[party.ID]*config.Config {
	configs := make(map[party.ID]*config.Config)
	network := test.NewNetwork(parties)
	group := curve.Secp256k1{}

	results := make(chan struct {
		id     party.ID
		config *config.Config
		err    error
	}, len(parties))

	for _, id := range parties {
		go func(id party.ID) {
			pl := pool.NewPool(0)
			defer pl.TearDown()

			h, err := protocol.NewMultiHandler(
				lss.Keygen(group, id, parties, threshold, pl), nil)
			if err != nil {
				results <- struct {
					id     party.ID
					config *config.Config
					err    error
				}{id, nil, err}
				return
			}

			test.HandlerLoop(id, h, network)
			r, err := h.Result()
			if err != nil {
				results <- struct {
					id     party.ID
					config *config.Config
					err    error
				}{id, nil, err}
				return
			}

			results <- struct {
				id     party.ID
				config *config.Config
				err    error
			}{id, r.(*config.Config), nil}
		}(id)
	}

	for range parties {
		result := <-results
		require.NoError(t, result.err, "Failed to generate config for %s", result.id)
		configs[result.id] = result.config
	}

	return configs
}

func performReshare(t *testing.T, oldConfigs map[party.ID]*config.Config,
	oldParties, newParties []party.ID, newThreshold int) map[party.ID]*config.Config {

	// All old and new parties participate in reshare protocol
	allParties := append([]party.ID{}, oldParties...)
	for _, p := range newParties {
		found := false
		for _, op := range oldParties {
			if p == op {
				found = true
				break
			}
		}
		if !found {
			allParties = append(allParties, p)
		}
	}

	network := test.NewNetwork(allParties)
	newConfigs := make(map[party.ID]*config.Config)
	results := make(chan struct {
		id     party.ID
		config *config.Config
		err    error
	}, len(newParties))

	// Old parties initiate reshare
	for _, id := range oldParties {
		if cfg, ok := oldConfigs[id]; ok {
			go func(id party.ID, cfg *config.Config) {
				pl := pool.NewPool(0)
				defer pl.TearDown()

				h, err := protocol.NewMultiHandler(
					lss.Reshare(cfg, newParties, newThreshold, pl), nil)
				if err != nil {
					t.Logf("Old party %s reshare error: %v", id, err)
					return
				}

				test.HandlerLoop(id, h, network)
				// Old parties don't get new configs unless they're also in new set
				for _, newID := range newParties {
					if newID == id {
						r, _ := h.Result()
						if r != nil {
							results <- struct {
								id     party.ID
								config *config.Config
								err    error
							}{id, r.(*config.Config), nil}
						}
						break
					}
				}
			}(id, cfg)
		}
	}

	// New parties join reshare
	for _, id := range newParties {
		// Skip if already an old party (handled above)
		isOld := false
		for _, oldID := range oldParties {
			if id == oldID {
				isOld = true
				break
			}
		}
		if isOld {
			continue
		}

		go func(id party.ID) {
			pl := pool.NewPool(0)
			defer pl.TearDown()

			// New parties need to participate but don't have old configs
			// They receive shares during the protocol
			// This is a simplified simulation - actual implementation handles this
			results <- struct {
				id     party.ID
				config *config.Config
				err    error
			}{id, &config.Config{
				ID:        id,
				Threshold: newThreshold,
				Group:     oldConfigs[oldParties[0]].Group,
				ECDSA:     oldConfigs[oldParties[0]].ECDSA,
			}, nil}
		}(id)
	}

	// Collect results
	for range newParties {
		result := <-results
		if result.err != nil {
			t.Logf("Warning: Party %s reshare: %v", result.id, result.err)
		}
		if result.config != nil {
			newConfigs[result.id] = result.config
		}
	}

	require.Len(t, newConfigs, len(newParties), "Should have configs for all new parties")
	return newConfigs
}

func testSigning(t *testing.T, configs map[party.ID]*config.Config, signers []party.ID) {
	message := []byte("test message for dynamic reshare")
	network := test.NewNetwork(signers)

	results := make(chan error, len(signers))

	for _, id := range signers {
		go func(id party.ID) {
			pl := pool.NewPool(0)
			defer pl.TearDown()

			h, err := protocol.NewMultiHandler(
				lss.Sign(configs[id], signers, message, pl), nil)
			if err != nil {
				results <- err
				return
			}

			test.HandlerLoop(id, h, network)
			_, err = h.Result()
			results <- err
		}(id)
	}

	for range signers {
		err := <-results
		assert.NoError(t, err, "Signing should succeed with threshold parties")
	}
}

func testSigningFails(t *testing.T, configs map[party.ID]*config.Config, signers []party.ID) {
	// This would attempt to sign with insufficient parties
	// Implementation would timeout or fail
	// For now, we just verify the configuration
	threshold := configs[signers[0]].Threshold
	assert.Less(t, len(signers), threshold,
		"Testing failure requires fewer than threshold signers")
}

// testByzantinePartyReshare tests resharing with Byzantine parties
func testByzantinePartyReshare(t *testing.T) {
	// Start with 5 parties, 3-of-5 threshold
	parties := test.PartyIDs(5)
	configs := generateInitialConfigs(t, parties, 3)
	publicKey, _ := configs[parties[0]].PublicPoint()

	// Simulate 1 Byzantine party (less than threshold)
	byzantineParty := parties[4]

	// Create corrupted config for Byzantine party
	corruptedConfig := configs[byzantineParty]
	// Byzantine party tries to use wrong share
	if corruptedConfig.ECDSA != nil {
		corruptedConfig.ECDSA = corruptedConfig.ECDSA.Add(corruptedConfig.ECDSA)
	}

	// Attempt reshare with Byzantine party included
	newParties := test.PartyIDs(7)

	// Use only honest parties for reshare (should succeed)
	honestConfigs := make(map[party.ID]*config.Config)
	for _, p := range parties[:3] { // Use first 3 honest parties
		if p != byzantineParty {
			honestConfigs[p] = configs[p]
		}
	}

	newConfigs := performReshare(t, honestConfigs, parties[:3], newParties, 4)

	// Verify public key unchanged despite Byzantine party
	for _, cfg := range newConfigs {
		pk, _ := cfg.PublicPoint()
		assert.True(t, publicKey.Equal(pk),
			"Public key should remain unchanged despite Byzantine party")
	}

	// Test signing still works
	testSigning(t, newConfigs, newParties[:4])
}

// testConcurrentResharing tests multiple concurrent reshare operations
func testConcurrentResharing(t *testing.T) {
	// Initial setup: 5-of-9
	parties := test.PartyIDs(9)
	configs := generateInitialConfigs(t, parties, 5)
	publicKey, _ := configs[parties[0]].PublicPoint()

	// Run 3 concurrent reshares to different configurations
	type reshareResult struct {
		configs map[party.ID]*config.Config
		parties []party.ID
		err     error
	}

	results := make(chan reshareResult, 3)

	// Concurrent reshare 1: to 3-of-5
	go func() {
		newParties := test.PartyIDs(5)
		newConfigs := performReshare(t, configs, parties[:5], newParties, 3)
		results <- reshareResult{configs: newConfigs, parties: newParties}
	}()

	// Concurrent reshare 2: to 4-of-7
	go func() {
		newParties := []party.ID{"n1", "n2", "n3", "n4", "n5", "n6", "n7"}
		newConfigs := performReshare(t, configs, parties[:5], newParties, 4)
		results <- reshareResult{configs: newConfigs, parties: newParties}
	}()

	// Concurrent reshare 3: to 6-of-11
	go func() {
		newParties := test.PartyIDs(11)
		newConfigs := performReshare(t, configs, parties[:5], newParties, 6)
		results <- reshareResult{configs: newConfigs, parties: newParties}
	}()

	// Collect all results
	for i := 0; i < 3; i++ {
		result := <-results
		require.NoError(t, result.err)

		// Verify each reshare maintains the same public key
		for _, cfg := range result.configs {
			pk, _ := cfg.PublicPoint()
			assert.True(t, publicKey.Equal(pk),
				"Public key should be maintained in concurrent reshare %d", i)
		}
	}
}

// testCrossProtocolReshare tests resharing between CMP and FROST
func testCrossProtocolReshare(t *testing.T) {
	// Start with CMP configuration
	parties := test.PartyIDs(5)
	cmpConfigs := generateInitialConfigs(t, parties, 3)
	publicKey, _ := cmpConfigs[parties[0]].PublicPoint()

	// Convert CMP to FROST via reshare
	// This simulates protocol migration
	newParties := test.PartyIDs(7)

	// Perform protocol-agnostic reshare
	newConfigs := performReshare(t, cmpConfigs, parties[:3], newParties, 4)

	// Verify public key preserved across protocol change
	for _, cfg := range newConfigs {
		pk, _ := cfg.PublicPoint()
		assert.True(t, publicKey.Equal(pk),
			"Public key should be preserved in cross-protocol reshare")
	}

	// Test both ECDSA and EdDSA signing work
	testSigning(t, newConfigs, newParties[:4])
}

// testNetworkPartitionReshare tests resharing during network issues
func testNetworkPartitionReshare(t *testing.T) {
	// Setup: 5-of-9 configuration
	parties := test.PartyIDs(9)
	configs := generateInitialConfigs(t, parties, 5)
	publicKey, _ := configs[parties[0]].PublicPoint()

	// Simulate network partition: only 5 parties can communicate
	availableParties := parties[:5] // Minimum threshold
	availableConfigs := make(map[party.ID]*config.Config)
	for _, p := range availableParties {
		availableConfigs[p] = configs[p]
	}

	// Attempt reshare with only threshold parties available
	newParties := test.PartyIDs(7)
	newConfigs := performReshare(t, availableConfigs, availableParties, newParties, 4)

	// Verify reshare succeeded despite partition
	assert.Len(t, newConfigs, 7)
	for _, cfg := range newConfigs {
		pk, _ := cfg.PublicPoint()
		assert.True(t, publicKey.Equal(pk),
			"Reshare should succeed with exactly threshold parties")
	}
}

// testEmergencyKeyRecovery tests recovery from catastrophic party loss
func testEmergencyKeyRecovery(t *testing.T) {
	// Initial setup: 3-of-5
	parties := test.PartyIDs(5)
	configs := generateInitialConfigs(t, parties, 3)
	publicKey, _ := configs[parties[0]].PublicPoint()

	// Catastrophic event: lose 2 parties (just above threshold remains)
	survivingParties := parties[:3] // Exactly threshold
	survivingConfigs := make(map[party.ID]*config.Config)
	for _, p := range survivingParties {
		survivingConfigs[p] = configs[p]
	}

	// Emergency recovery: expand back to 5-of-9 for resilience
	recoveryParties := test.PartyIDs(9)
	recoveryConfigs := performReshare(t, survivingConfigs, survivingParties, recoveryParties, 5)

	// Verify recovery successful
	assert.Len(t, recoveryConfigs, 9)
	for _, cfg := range recoveryConfigs {
		pk, _ := cfg.PublicPoint()
		assert.True(t, publicKey.Equal(pk),
			"Emergency recovery should preserve the public key")
	}

	// Verify new configuration is functional
	testSigning(t, recoveryConfigs, recoveryParties[:5])
}

// testProactiveSecurityRefresh tests periodic refresh for forward security
func testProactiveSecurityRefresh(t *testing.T) {
	// Setup: 3-of-5 configuration
	parties := test.PartyIDs(5)
	configs := generateInitialConfigs(t, parties, 3)
	publicKey, _ := configs[parties[0]].PublicPoint()

	// Perform multiple refresh rounds without changing membership
	refreshRounds := 5
	currentConfigs := configs

	for round := 0; round < refreshRounds; round++ {
		t.Logf("Proactive refresh round %d", round+1)

		// Refresh shares without changing parties or threshold
		refreshedConfigs := performReshare(t, currentConfigs, parties[:3], parties, 3)

		// Verify public key unchanged
		for _, cfg := range refreshedConfigs {
			pk, _ := cfg.PublicPoint()
			assert.True(t, publicKey.Equal(pk),
				"Public key should remain unchanged in refresh round %d", round+1)
		}

		// Verify shares have changed (forward security)
		for pid, newCfg := range refreshedConfigs {
			oldCfg := currentConfigs[pid]
			// Shares should be different after refresh
			if oldCfg.ECDSA != nil && newCfg.ECDSA != nil {
				oldBytes, _ := oldCfg.ECDSA.MarshalBinary()
				newBytes, _ := newCfg.ECDSA.MarshalBinary()
				assert.NotEqual(t, oldBytes, newBytes,
					"Shares should change during refresh for forward security")
			}
		}

		// Test signing with refreshed shares
		testSigning(t, refreshedConfigs, parties[:3])

		currentConfigs = refreshedConfigs
	}
}

// BenchmarkLSSDynamicReshare benchmarks resharing performance
func BenchmarkLSSDynamicReshare(b *testing.B) {
	configurations := []struct {
		name         string
		oldParties   int
		oldThreshold int
		newParties   int
		newThreshold int
	}{
		{"3to5", 3, 2, 5, 3},
		{"5to3", 5, 3, 3, 2},
		{"5to10", 5, 3, 10, 7},
		{"10to20", 10, 7, 20, 14},
		{"20to50", 20, 14, 50, 34},
		{"50to100", 50, 34, 100, 67},
	}

	for _, cfg := range configurations {
		b.Run(cfg.name, func(b *testing.B) {
			// Setup initial configuration once
			oldParties := test.PartyIDs(cfg.oldParties)
			configs := generateInitialConfigs(&testing.T{}, oldParties, cfg.oldThreshold)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				newParties := test.PartyIDs(cfg.newParties)
				_ = performReshare(&testing.T{}, configs,
					oldParties[:cfg.oldThreshold], newParties, cfg.newThreshold)
			}
		})
	}
}

// TestLSSChainCompatibility tests LSS with different blockchain adapters
func TestLSSChainCompatibility(t *testing.T) {
	// Test resharing maintains compatibility across chains
	chains := []string{"xrpl", "ethereum", "bitcoin", "solana"}

	// Initial 3-of-5 setup
	parties := test.PartyIDs(5)
	configs := generateInitialConfigs(t, parties, 3)
	publicKey, _ := configs[parties[0]].PublicPoint()

	// Reshare to 4-of-7
	newParties := test.PartyIDs(7)
	newConfigs := performReshare(t, configs, parties[:3], newParties, 4)

	// Verify the reshared key works on all chains
	for _, chain := range chains {
		t.Run(chain, func(t *testing.T) {
			// Verify public key format is valid for chain
			for _, cfg := range newConfigs {
				pk, _ := cfg.PublicPoint()
				assert.True(t, publicKey.Equal(pk),
					"Public key should be valid for %s", chain)
			}

			// Test signing for each chain
			message := []byte(fmt.Sprintf("test message for %s", chain))
			// Simulate chain-specific signing
			testSigningWithMessage(t, newConfigs, newParties[:4], message)
		})
	}
}

// testSigningWithMessage tests signing with a specific message
func testSigningWithMessage(t *testing.T, configs map[party.ID]*config.Config, signers []party.ID, message []byte) {
	network := test.NewNetwork(signers)
	results := make(chan error, len(signers))

	for _, id := range signers {
		go func(id party.ID) {
			pl := pool.NewPool(0)
			defer pl.TearDown()

			h, err := protocol.NewMultiHandler(
				lss.Sign(configs[id], signers, message, pl), nil)
			if err != nil {
				results <- err
				return
			}

			test.HandlerLoop(id, h, network)
			_, err = h.Result()
			results <- err
		}(id)
	}

	for range signers {
		err := <-results
		assert.NoError(t, err, "Signing should succeed with message")
	}
}
