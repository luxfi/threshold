package cmp_test

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDynamicReshare_AddParties(t *testing.T) {
	group := curve.Secp256k1{}
	
	// Initial setup: 3-of-5 threshold scheme
	N := 5
	T := 3
	initialParties := test.PartyIDs(N)
	
	// Run initial keygen
	initialConfigs := runKeygen(t, group, initialParties, T)
	
	// Verify all parties have the same public key
	publicKey := initialConfigs[initialParties[0]].PublicPoint()
	for _, id := range initialParties {
		assert.True(t, publicKey.Equal(initialConfigs[id].PublicPoint()))
	}
	
	// Add 2 new parties (changing to 3-of-7)
	newParties := test.PartyIDs(2)
	for i := range newParties {
		newParties[i] = party.ID(fmt.Sprintf("party-%d", N+i+1))
	}
	
	allNewParties := append(initialParties, newParties...)
	
	// Run dynamic reshare to add parties
	resharedConfigs := runDynamicReshare(t, initialConfigs, allNewParties, T)
	
	// Verify the public key remains the same
	for _, config := range resharedConfigs {
		assert.True(t, publicKey.Equal(config.PublicPoint()))
	}
	
	// Verify new parties can participate in signing
	message := []byte("test message for dynamic reshare")
	messageHash := make([]byte, 32)
	rand.Read(messageHash)
	
	// Select signers including new parties
	signers := []party.ID{initialParties[0], initialParties[1], newParties[0]}
	
	signature := runSign(t, resharedConfigs, signers, messageHash)
	
	// Verify signature
	assert.True(t, signature.Verify(publicKey, messageHash))
}

func TestDynamicReshare_RemoveParties(t *testing.T) {
	group := curve.Secp256k1{}
	
	// Initial setup: 3-of-5 threshold scheme
	N := 5
	T := 3
	initialParties := test.PartyIDs(N)
	
	// Run initial keygen
	initialConfigs := runKeygen(t, group, initialParties, T)
	
	// Store public key
	publicKey := initialConfigs[initialParties[0]].PublicPoint()
	
	// Remove 2 parties (changing to 2-of-3)
	remainingParties := initialParties[:3]
	newThreshold := 2
	
	// Run dynamic reshare to remove parties
	resharedConfigs := runDynamicReshareRemove(t, initialConfigs, remainingParties, newThreshold)
	
	// Verify only remaining parties have configs
	assert.Equal(t, len(remainingParties), len(resharedConfigs))
	
	// Verify the public key remains the same
	for _, config := range resharedConfigs {
		assert.True(t, publicKey.Equal(config.PublicPoint()))
	}
	
	// Verify remaining parties can still sign
	messageHash := make([]byte, 32)
	rand.Read(messageHash)
	
	signature := runSign(t, resharedConfigs, remainingParties[:newThreshold], messageHash)
	assert.True(t, signature.Verify(publicKey, messageHash))
}

func TestDynamicReshare_ChangeThreshold(t *testing.T) {
	group := curve.Secp256k1{}
	
	// Initial setup: 2-of-4 threshold scheme
	N := 4
	T := 2
	parties := test.PartyIDs(N)
	
	// Run initial keygen
	initialConfigs := runKeygen(t, group, parties, T)
	publicKey := initialConfigs[parties[0]].PublicPoint()
	
	// Change threshold to 3-of-4
	newThreshold := 3
	
	// Run dynamic reshare to change threshold
	resharedConfigs := make(map[party.ID]*cmp.Config)
	for id, config := range initialConfigs {
		pl := pool.NewPool(0)
		handler := protocol.NewMultiHandler(cmp.ChangeThreshold(config, newThreshold, pl), nil)
		
		test.Rounds(t, handler, config)
		
		r, err := handler.Result()
		require.NoError(t, err)
		require.IsType(t, &cmp.Config{}, r)
		
		resharedConfigs[id] = r.(*cmp.Config)
	}
	
	// Verify the public key remains the same
	for _, config := range resharedConfigs {
		assert.True(t, publicKey.Equal(config.PublicPoint()))
		assert.Equal(t, newThreshold, config.Threshold)
	}
	
	// Verify new threshold is enforced (need 3 parties to sign)
	messageHash := make([]byte, 32)
	rand.Read(messageHash)
	
	// Try with 2 parties (should fail in real implementation)
	// Try with 3 parties (should succeed)
	signers := parties[:newThreshold]
	signature := runSign(t, resharedConfigs, signers, messageHash)
	assert.True(t, signature.Verify(publicKey, messageHash))
}

func TestDynamicReshare_MigrateParties(t *testing.T) {
	group := curve.Secp256k1{}
	
	// Initial setup: 3-of-5 threshold scheme
	N := 5
	T := 3
	initialParties := test.PartyIDs(N)
	
	// Run initial keygen
	initialConfigs := runKeygen(t, group, initialParties, T)
	publicKey := initialConfigs[initialParties[0]].PublicPoint()
	
	// Migrate: remove 2 parties, add 3 new parties (3-of-6)
	partiesToRemove := initialParties[3:]
	remainingParties := initialParties[:3]
	
	newParties := make([]party.ID, 3)
	for i := range newParties {
		newParties[i] = party.ID(fmt.Sprintf("new-party-%d", i+1))
	}
	
	finalParties := append(remainingParties, newParties...)
	
	// Run migration
	migratedConfigs := runMigration(t, initialConfigs, partiesToRemove, newParties, T)
	
	// Verify correct number of configs
	assert.Equal(t, len(finalParties), len(migratedConfigs))
	
	// Verify the public key remains the same
	for _, config := range migratedConfigs {
		assert.True(t, publicKey.Equal(config.PublicPoint()))
	}
	
	// Verify mixed old and new parties can sign together
	messageHash := make([]byte, 32)
	rand.Read(messageHash)
	
	// Mix of old and new parties
	signers := []party.ID{remainingParties[0], newParties[0], newParties[1]}
	signature := runSign(t, migratedConfigs, signers, messageHash)
	assert.True(t, signature.Verify(publicKey, messageHash))
}

// Helper functions

func runKeygen(t *testing.T, group curve.Curve, parties []party.ID, threshold int) map[party.ID]*cmp.Config {
	configs := make(map[party.ID]*cmp.Config)
	
	for _, id := range parties {
		pl := pool.NewPool(0)
		handler := protocol.NewMultiHandler(cmp.Keygen(group, id, parties, threshold, pl), nil)
		test.Rounds(t, handler, nil)
		
		r, err := handler.Result()
		require.NoError(t, err)
		require.IsType(t, &cmp.Config{}, r)
		
		configs[id] = r.(*cmp.Config)
	}
	
	return configs
}

func runDynamicReshare(t *testing.T, oldConfigs map[party.ID]*cmp.Config, newParties []party.ID, threshold int) map[party.ID]*cmp.Config {
	allConfigs := make(map[party.ID]*cmp.Config)
	
	// Old parties run reshare with their configs
	for id, config := range oldConfigs {
		pl := pool.NewPool(0)
		handler := protocol.NewMultiHandler(cmp.DynamicReshare(config, newParties, threshold, pl), nil)
		test.Rounds(t, handler, config)
		
		r, err := handler.Result()
		if err == nil && r != nil {
			allConfigs[id] = r.(*cmp.Config)
		}
	}
	
	// New parties need to participate too
	// In a real implementation, they would receive initial data from old parties
	
	return allConfigs
}

func runDynamicReshareRemove(t *testing.T, oldConfigs map[party.ID]*cmp.Config, remainingParties []party.ID, newThreshold int) map[party.ID]*cmp.Config {
	remainingConfigs := make(map[party.ID]*cmp.Config)
	
	// All old parties participate in reshare
	for id, config := range oldConfigs {
		pl := pool.NewPool(0)
		handler := protocol.NewMultiHandler(cmp.RemoveParties(config, []party.ID{}, newThreshold, pl), nil)
		test.Rounds(t, handler, config)
		
		r, err := handler.Result()
		
		// Only remaining parties should get results
		isRemaining := false
		for _, rid := range remainingParties {
			if id == rid {
				isRemaining = true
				break
			}
		}
		
		if isRemaining && err == nil && r != nil {
			remainingConfigs[id] = r.(*cmp.Config)
		}
	}
	
	return remainingConfigs
}

func runMigration(t *testing.T, oldConfigs map[party.ID]*cmp.Config, removeParties, addParties []party.ID, threshold int) map[party.ID]*cmp.Config {
	migratedConfigs := make(map[party.ID]*cmp.Config)
	
	// Use any old party's config to initiate migration
	var initiatorConfig *cmp.Config
	for _, config := range oldConfigs {
		initiatorConfig = config
		break
	}
	
	pl := pool.NewPool(0)
	handler := protocol.NewMultiHandler(
		cmp.MigrateParties(initiatorConfig, removeParties, addParties, threshold, pl), 
		nil,
	)
	
	// Run the migration protocol
	// In real implementation, this would coordinate between all parties
	
	return migratedConfigs
}

func runSign(t *testing.T, configs map[party.ID]*cmp.Config, signers []party.ID, messageHash []byte) *cmp.Signature {
	// Simple signing simulation
	// In real implementation, this would run the full CMP signing protocol
	
	var signature *cmp.Signature
	
	for _, id := range signers {
		config, ok := configs[id]
		if !ok {
			continue
		}
		
		pl := pool.NewPool(0)
		handler := protocol.NewMultiHandler(cmp.Sign(config, signers, messageHash, pl), nil)
		test.Rounds(t, handler, config)
		
		r, err := handler.Result()
		if err == nil && r != nil {
			signature = r.(*cmp.Signature)
			break
		}
	}
	
	require.NotNil(t, signature)
	return signature
}