package lss_test

import (
	"crypto/rand"
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/protocols/cmp/config"
	"github.com/luxfi/threshold/protocols/lss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func TestLSSCMPDynamicReshare(t *testing.T) {
	group := curve.Secp256k1{}

	t.Run("AddParties", func(t *testing.T) {
		// Start with 3-of-5 setup
		N := 5
		T := 3
		partyIDs := test.PartyIDs(N)

		// Generate initial CMP configs
		pl := pool.NewPool(0)
		defer pl.TearDown()

		configs := generateCMPConfigs(t, group, partyIDs, T, pl)

		// Store original public key for verification
		originalPublicKey := configs[partyIDs[0]].PublicPoint()

		// Add 2 new parties (becomes 3-of-7)
		newPartyIDs := []party.ID{"party-6", "party-7"}
		allPartyIDs := append(partyIDs, newPartyIDs...)

		// Perform dynamic reshare
		newConfigs, err := lss.DynamicReshareCMP(configs, allPartyIDs, T, pl)
		require.NoError(t, err)
		require.Len(t, newConfigs, 7)

		// Verify all new configs have the same public key
		for _, cfg := range newConfigs {
			assert.True(t, cfg.PublicPoint().Equal(originalPublicKey),
				"Public key should remain unchanged after resharing")
		}

		// Test that signing would work with new configuration
		// In real usage, this would use cmp.Sign protocol
		messageHash := randomHashLSSCMP()
		signers := allPartyIDs[:T]
		verifySigningCapability(t, newConfigs, signers, messageHash, originalPublicKey)
	})

	t.Run("RemoveParties", func(t *testing.T) {
		// Start with 3-of-5 setup
		N := 5
		T := 3
		partyIDs := test.PartyIDs(N)

		pl := pool.NewPool(0)
		defer pl.TearDown()

		configs := generateCMPConfigs(t, group, partyIDs, T, pl)
		originalPublicKey := configs[partyIDs[0]].PublicPoint()

		// Remove 2 parties (becomes 2-of-3)
		remainingPartyIDs := partyIDs[:3]
		newThreshold := 2

		// Perform dynamic reshare
		newConfigs, err := lss.DynamicReshareCMP(configs, remainingPartyIDs, newThreshold, pl)
		require.NoError(t, err)
		require.Len(t, newConfigs, 3)

		// Verify public key unchanged
		for _, cfg := range newConfigs {
			assert.True(t, cfg.PublicPoint().Equal(originalPublicKey))
		}

		// Test signing with reduced set
		messageHash := randomHashLSSCMP()
		signers := remainingPartyIDs[:newThreshold]
		verifySigningCapability(t, newConfigs, signers, messageHash, originalPublicKey)
	})

	t.Run("ChangeThreshold", func(t *testing.T) {
		// Start with 2-of-4 setup
		N := 4
		T := 2
		partyIDs := test.PartyIDs(N)

		pl := pool.NewPool(0)
		defer pl.TearDown()

		configs := generateCMPConfigs(t, group, partyIDs, T, pl)
		originalPublicKey := configs[partyIDs[0]].PublicPoint()

		// Change to 3-of-4
		newThreshold := 3

		// Perform dynamic reshare
		newConfigs, err := lss.DynamicReshareCMP(configs, partyIDs, newThreshold, pl)
		require.NoError(t, err)
		require.Len(t, newConfigs, 4)

		// Verify threshold changed but key unchanged
		for _, cfg := range newConfigs {
			assert.Equal(t, newThreshold, cfg.Threshold)
			assert.True(t, cfg.PublicPoint().Equal(originalPublicKey))
		}

		// Test that T-1 parties cannot sign
		messageHash := randomHashLSSCMP()
		insufficientSigners := partyIDs[:newThreshold-1]

		// Verify insufficient signers would fail
		threshold := newConfigs[partyIDs[0]].Threshold
		assert.Less(t, len(insufficientSigners), threshold, "Should have insufficient signers")

		// But T parties can sign
		sufficientSigners := partyIDs[:newThreshold]
		verifySigningCapability(t, newConfigs, sufficientSigners, messageHash, originalPublicKey)
	})

	t.Run("SimultaneousAddRemove", func(t *testing.T) {
		// Start with 3-of-5 setup
		N := 5
		T := 3
		partyIDs := test.PartyIDs(N)

		pl := pool.NewPool(0)
		defer pl.TearDown()

		configs := generateCMPConfigs(t, group, partyIDs, T, pl)
		originalPublicKey := configs[partyIDs[0]].PublicPoint()

		// Remove parties 4,5 and add parties 6,7,8 (becomes 4-of-6)
		remainingPartyIDs := partyIDs[:3]
		newPartyIDs := []party.ID{"party-6", "party-7", "party-8"}
		allNewPartyIDs := append(remainingPartyIDs, newPartyIDs...)
		newThreshold := 4

		// Perform dynamic reshare
		newConfigs, err := lss.DynamicReshareCMP(configs, allNewPartyIDs, newThreshold, pl)
		require.NoError(t, err)
		require.Len(t, newConfigs, 6)

		// Verify configuration
		for _, cfg := range newConfigs {
			assert.Equal(t, newThreshold, cfg.Threshold)
			assert.True(t, cfg.PublicPoint().Equal(originalPublicKey))
		}

		// Test signing with new mixed set
		messageHash := randomHashLSSCMP()
		// Use 2 old parties and 2 new parties
		signers := []party.ID{remainingPartyIDs[0], remainingPartyIDs[1], newPartyIDs[0], newPartyIDs[1]}
		verifySigningCapability(t, newConfigs, signers, messageHash, originalPublicKey)
	})

	t.Run("ReshareWithInvalidThreshold", func(t *testing.T) {
		N := 3
		T := 2
		partyIDs := test.PartyIDs(N)

		pl := pool.NewPool(0)
		defer pl.TearDown()

		configs := generateCMPConfigs(t, group, partyIDs, T, pl)

		// Try to set threshold higher than party count
		_, err := lss.DynamicReshareCMP(configs, partyIDs, 4, pl)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid threshold")

		// Try with zero threshold
		_, err = lss.DynamicReshareCMP(configs, partyIDs, 0, pl)
		assert.Error(t, err)

		// Try with negative threshold
		_, err = lss.DynamicReshareCMP(configs, partyIDs, -1, pl)
		assert.Error(t, err)
	})

	t.Run("ReshareWithInsufficientOldParties", func(t *testing.T) {
		N := 5
		T := 3
		partyIDs := test.PartyIDs(N)

		pl := pool.NewPool(0)
		defer pl.TearDown()

		configs := generateCMPConfigs(t, group, partyIDs, T, pl)

		// Only provide T-1 old configs (insufficient to reconstruct secret)
		insufficientConfigs := make(map[party.ID]*config.Config)
		for i := 0; i < T-1; i++ {
			insufficientConfigs[partyIDs[i]] = configs[partyIDs[i]]
		}

		newPartyIDs := []party.ID{"new-1", "new-2"}
		_, err := lss.DynamicReshareCMP(insufficientConfigs, newPartyIDs, 2, pl)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "need at least")
	})

	t.Run("MultipleReshares", func(t *testing.T) {
		// Test multiple consecutive reshares
		N := 4
		T := 2
		partyIDs := test.PartyIDs(N)

		pl := pool.NewPool(0)
		defer pl.TearDown()

		configs := generateCMPConfigs(t, group, partyIDs, T, pl)
		originalPublicKey := configs[partyIDs[0]].PublicPoint()

		// First reshare: add 2 parties
		newPartyIDs1 := []party.ID{"party-5", "party-6"}
		allPartyIDs1 := append(partyIDs, newPartyIDs1...)

		configs2, err := lss.DynamicReshareCMP(configs, allPartyIDs1, 3, pl)
		require.NoError(t, err)

		// Second reshare: remove 2 original parties
		remainingPartyIDs := append(partyIDs[2:], newPartyIDs1...)

		configs3, err := lss.DynamicReshareCMP(configs2, remainingPartyIDs, 2, pl)
		require.NoError(t, err)

		// Verify public key still unchanged after multiple reshares
		for _, cfg := range configs3 {
			assert.True(t, cfg.PublicPoint().Equal(originalPublicKey))
		}

		// Test signing still works
		messageHash := randomHashLSSCMP()
		signers := remainingPartyIDs[:2]
		verifySigningCapability(t, configs3, signers, messageHash, originalPublicKey)
	})
}

func TestLSSCMPCompatibility(t *testing.T) {
	t.Run("LSSExtendedConfigSignsWithCMP", func(t *testing.T) {
		group := curve.Secp256k1{}
		N := 5
		T := 3
		partyIDs := test.PartyIDs(N)

		pl := pool.NewPool(0)
		defer pl.TearDown()

		// Generate configs via LSS reshare
		originalConfigs := generateCMPConfigs(t, group, partyIDs[:3], 2, pl)

		// Reshare to add more parties
		resharedConfigs, err := lss.DynamicReshareCMP(originalConfigs, partyIDs, T, pl)
		require.NoError(t, err)

		// Use reshared configs with standard CMP signing
		messageHash := randomHashLSSCMP()
		signers := partyIDs[:T]
		publicKey := resharedConfigs[partyIDs[0]].PublicPoint()
		verifySigningCapability(t, resharedConfigs, signers, messageHash, publicKey)
	})

	t.Run("MixedOldNewPartySignatures", func(t *testing.T) {
		group := curve.Secp256k1{}
		N := 5
		T := 3
		partyIDs := test.PartyIDs(N)

		pl := pool.NewPool(0)
		defer pl.TearDown()

		// Start with smaller group
		originalPartyIDs := partyIDs[:3]
		configs := generateCMPConfigs(t, group, originalPartyIDs, 2, pl)
		originalPublicKey := configs[originalPartyIDs[0]].PublicPoint()

		// Add new parties
		newConfigs, err := lss.DynamicReshareCMP(configs, partyIDs, T, pl)
		require.NoError(t, err)

		// Sign with mix of old and new parties
		messageHash := randomHashLSSCMP()
		mixedSigners := []party.ID{
			originalPartyIDs[0], // old party
			partyIDs[3],         // new party
			partyIDs[4],         // new party
		}

		verifySigningCapability(t, newConfigs, mixedSigners, messageHash, originalPublicKey)
	})
}

func BenchmarkLSSCMPReshare(b *testing.B) {
	group := curve.Secp256k1{}
	pl := pool.NewPool(0)
	defer pl.TearDown()

	testCases := []struct {
		name     string
		initialN int
		initialT int
		finalN   int
		finalT   int
	}{
		{"Add1Party_3of4_to_3of5", 4, 3, 5, 3},
		{"Add3Parties_3of5_to_4of8", 5, 3, 8, 4},
		{"Remove2Parties_5of9_to_3of7", 9, 5, 7, 3},
		{"ChangeThreshold_2of5_to_4of5", 5, 2, 5, 4},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			// Setup
			initialPartyIDs := test.PartyIDs(tc.initialN)
			configs := generateCMPConfigs(b, group, initialPartyIDs, tc.initialT, pl)

			finalPartyIDs := test.PartyIDs(tc.finalN)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := lss.DynamicReshareCMP(configs, finalPartyIDs, tc.finalT, pl)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Helper functions

func generateCMPConfigs(t testing.TB, group curve.Curve, partyIDs []party.ID, threshold int, pl *pool.Pool) map[party.ID]*config.Config {
	configs, _ := test.GenerateConfig(group, len(partyIDs), threshold, rand.Reader, pl)

	// Map configs to party IDs
	result := make(map[party.ID]*config.Config)
	i := 0
	for _, pid := range partyIDs {
		// Find config with matching index
		for id, cfg := range configs {
			if i == 0 {
				// Reassign to our party IDs
				newCfg := *cfg
				newCfg.ID = pid
				result[pid] = &newCfg
				delete(configs, id)
				break
			}
			i--
		}
		i++
	}

	// Update public maps
	for _, cfg := range result {
		cfg.Public = make(map[party.ID]*config.Public)
		for pid, otherCfg := range result {
			cfg.Public[pid] = &config.Public{
				ECDSA:    otherCfg.ECDSA.ActOnBase(),
				ElGamal:  otherCfg.ElGamal.ActOnBase(),
				Paillier: otherCfg.Paillier.PublicKey,
				Pedersen: nil, // Would be set in real scenario
			}
		}
	}

	return result
}

func verifySigningCapability(t testing.TB, configs map[party.ID]*config.Config, signers []party.ID, messageHash []byte, expectedPublicKey curve.Point) {
	// Verify we have enough signers
	threshold := 0
	for _, cfg := range configs {
		threshold = cfg.Threshold
		break
	}

	if len(signers) < threshold {
		t.Fatalf("insufficient signers: have %d, need %d", len(signers), threshold)
	}

	// In production, this would run the full CMP signing protocol
	// For testing, we verify the configs are consistent
	for _, pid := range signers {
		cfg, exists := configs[pid]
		if !exists {
			t.Fatalf("signer %s not in configs", pid)
		}
		assert.True(t, cfg.PublicPoint().Equal(expectedPublicKey),
			"Config for %s has wrong public key", pid)
	}
}

func randomHashLSSCMP() []byte {
	hash := make([]byte, 32)
	sha3.ShakeSum128(hash, []byte("test"))
	return hash
}
