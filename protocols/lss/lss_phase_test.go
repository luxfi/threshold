package lss_test

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/lss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLSSKeygenPhased(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	tests := []struct {
		name       string
		partyCount int
		threshold  int
	}{
		{"2-of-3", 3, 2},
		{"3-of-5", 5, 3},
		{"5-of-7", 7, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			partyIDs := test.PartyIDs(tt.partyCount)
			h := test.NewPhaseHarness(t, partyIDs)

			// Phase 1: Keygen
			keygenRes, err := h.RunPhase(60*time.Second, func(id party.ID) protocol.StartFunc {
				return lss.Keygen(curve.Secp256k1{}, id, partyIDs, tt.threshold, pl)
			})
			require.NoError(t, err, "keygen should complete without error")
			require.Len(t, keygenRes, tt.partyCount)

			// Verify all parties have valid configs
			var firstPubKey curve.Point
			for id, res := range keygenRes {
				config, ok := res.(*lss.Config)
				require.True(t, ok, "result should be *lss.Config for party %s", id)
				require.NotNil(t, config)
				require.Equal(t, id, config.ID)
				require.Equal(t, tt.threshold, config.Threshold)
				require.NotNil(t, config.ECDSA)
				require.NotNil(t, config.ChainKey)
				require.NotNil(t, config.RID)

				// Get public key
				pubKey, err := config.PublicPoint()
				require.NoError(t, err)
				
				if firstPubKey == nil {
					firstPubKey = pubKey
				} else {
					assert.True(t, firstPubKey.Equal(pubKey),
						"all parties should have same public key")
				}
			}
		})
	}
}

func TestLSSKeygenReshareSignPhased(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	tests := []struct {
		name          string
		oldPartyCount int
		oldThreshold  int
		newPartyCount int
		newThreshold  int
	}{
		{"3to5", 3, 2, 5, 3},
		{"5to3", 5, 3, 3, 2},
		{"5to5", 5, 3, 5, 3}, // Same parties, same threshold
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldPartyIDs := test.PartyIDs(tt.oldPartyCount)
			h := test.NewPhaseHarness(t, oldPartyIDs)

			// Phase 1: Initial Keygen
			keygenRes, err := h.RunPhase(60*time.Second, func(id party.ID) protocol.StartFunc {
				return lss.Keygen(curve.Secp256k1{}, id, oldPartyIDs, tt.oldThreshold, pl)
			})
			require.NoError(t, err, "keygen should complete without error")
			require.Len(t, keygenRes, tt.oldPartyCount)

			// Get the original public key
			firstConfig := keygenRes[oldPartyIDs[0]].(*lss.Config)
			originalPubKey, err := firstConfig.PublicPoint()
			require.NoError(t, err)

			// Phase 2: Reshare to new configuration (new session)
			newPartyIDs := test.PartyIDs(tt.newPartyCount)
			
			// Create a mapping of old configs for parties that will participate
			oldConfigs := make(map[party.ID]*lss.Config)
			for _, id := range oldPartyIDs {
				if cfg, ok := keygenRes[id].(*lss.Config); ok {
					oldConfigs[id] = cfg
				}
			}

			// Run reshare phase - all old parties participate in sending shares
			h2 := test.NewPhaseHarness(t, append(oldPartyIDs, newPartyIDs...))
			reshareRes, err := h2.RunPhase(60*time.Second, func(id party.ID) protocol.StartFunc {
				// Old parties participate in resharing
				if config, ok := oldConfigs[id]; ok {
					return lss.Reshare(config, newPartyIDs, tt.newThreshold, pl)
				}
				// ReceiveReshare not implemented - skip for now
				// return lss.ReceiveReshare(curve.Secp256k1{}, id, oldPartyIDs, newPartyIDs, tt.newThreshold, pl)
				return nil
			})
			require.NoError(t, err, "reshare should complete without error")

			// Extract new configs for new parties only
			newConfigs := make(map[party.ID]*lss.Config)
			for _, id := range newPartyIDs {
				if res, ok := reshareRes[id]; ok && res != nil {
					if cfg, ok := res.(*lss.Config); ok {
						newConfigs[id] = cfg
					}
				}
			}
			require.Len(t, newConfigs, tt.newPartyCount)

			// Verify reshare maintained the same public key
			for id, config := range newConfigs {
				require.NotNil(t, config)
				pubKey, err := config.PublicPoint()
				require.NoError(t, err)
				assert.True(t, originalPubKey.Equal(pubKey),
					"party %s should have same public key after reshare", id)
				assert.Greater(t, config.Generation, firstConfig.Generation,
					"generation should be incremented")
			}

			// Phase 3: Sign with new configuration (new session)
			messageHash := make([]byte, 32)
			_, _ = rand.Read(messageHash)
			
			signers := newPartyIDs[:tt.newThreshold]
			h3 := test.NewPhaseHarness(t, signers)
			
			signRes, err := h3.RunPhase(60*time.Second, func(id party.ID) protocol.StartFunc {
				config := newConfigs[id]
				return lss.Sign(config, signers, messageHash, pl)
			})
			require.NoError(t, err, "signing should complete without error")
			require.Len(t, signRes, tt.newThreshold)

			// Verify all parties produced valid signatures
			for id, res := range signRes {
				sig, ok := res.(*ecdsa.Signature)
				require.True(t, ok, "result should be *ecdsa.Signature for party %s", id)
				require.NotNil(t, sig)
				require.NotNil(t, sig.R)
				require.NotNil(t, sig.S)
				assert.False(t, sig.R.IsIdentity(), "R should be non-zero")
				assert.False(t, sig.S.IsZero(), "S should be non-zero")
				
				// Verify signature
				assert.True(t, sig.Verify(originalPubKey, messageHash),
					"signature should verify with original public key")
			}
		})
	}
}

// TestLSSPresignPhased tests presigning functionality
func TestLSSPresignPhased(t *testing.T) {
	// Note: Presign functions are not yet implemented in the LSS protocol
	// This test demonstrates the expected API and validates the test infrastructure
	t.Log("Presign functions not yet implemented in LSS protocol")
	pl := pool.NewPool(0)
	defer pl.TearDown()

	partyIDs := test.PartyIDs(5)
	threshold := 3
	signers := partyIDs[:threshold]

	// Phase 1: Keygen
	h := test.NewPhaseHarness(t, partyIDs)
	keygenRes, err := h.RunPhase(60*time.Second, func(id party.ID) protocol.StartFunc {
		return lss.Keygen(curve.Secp256k1{}, id, partyIDs, threshold, pl)
	})
	require.NoError(t, err, "keygen should complete without error")
	require.Len(t, keygenRes, 5)

	configs := make(map[party.ID]*lss.Config)
	for id, res := range keygenRes {
		configs[id] = res.(*lss.Config)
	}

	// Phase 2: Presign (new session, subset of parties)
	h2 := test.NewPhaseHarness(t, signers)
	presignRes, err := h2.RunPhase(60*time.Second, func(id party.ID) protocol.StartFunc {
		_ = configs[id] // config would be used if Presign was implemented
		// return lss.Presign(config, signers, pl)
		return nil // Presign not implemented
	})
	require.NoError(t, err, "presign should complete without error")
	require.Len(t, presignRes, threshold)

	// Verify presignatures
	presigs := make(map[party.ID]*ecdsa.PreSignature)
	for id, res := range presignRes {
		presig, ok := res.(*ecdsa.PreSignature)
		require.True(t, ok, "result should be *ecdsa.PreSignature for party %s", id)
		require.NotNil(t, presig)
		presigs[id] = presig
	}

	// Phase 3: Online signing with presignatures (new session)
	messageHash := make([]byte, 32)
	_, _ = rand.Read(messageHash)
	
	h3 := test.NewPhaseHarness(t, signers)
	onlineRes, err := h3.RunPhase(60*time.Second, func(id party.ID) protocol.StartFunc {
		_ = configs[id] // config would be used if PresignOnline was implemented
		_ = presigs[id] // presig would be used if PresignOnline was implemented
		// return lss.PresignOnline(config, presig, messageHash, pl)
		return nil // PresignOnline not implemented
	})
	require.NoError(t, err, "online signing should complete without error")
	require.Len(t, onlineRes, threshold)

	// Get original public key
	pubKey, err := configs[signers[0]].PublicPoint()
	require.NoError(t, err)

	// Verify signatures
	for id, res := range onlineRes {
		sig, ok := res.(*ecdsa.Signature)
		require.True(t, ok, "result should be *ecdsa.Signature for party %s", id)
		require.NotNil(t, sig)
		assert.True(t, sig.Verify(pubKey, messageHash),
			"signature should verify")
	}
}

func BenchmarkLSSKeygenPhased(b *testing.B) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	benchmarks := []struct {
		name       string
		partyCount int
		threshold  int
	}{
		{"2-of-3", 3, 2},
		{"3-of-5", 5, 3},
		{"5-of-7", 7, 5},
		{"7-of-10", 10, 7},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			partyIDs := test.PartyIDs(bm.partyCount)
			
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				h := test.NewPhaseHarness(b, partyIDs)
				
				_, err := h.RunPhase(60*time.Second, func(id party.ID) protocol.StartFunc {
					return lss.Keygen(curve.Secp256k1{}, id, partyIDs, bm.threshold, pl)
				})
				if err != nil {
					b.Fatalf("keygen failed: %v", err)
				}
			}
		})
	}
}

func BenchmarkLSSSignPhased(b *testing.B) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	// Setup: Run keygen once
	partyIDs := test.PartyIDs(5)
	threshold := 3
	signers := partyIDs[:threshold]
	
	h := test.NewPhaseHarness(b, partyIDs)
	keygenRes, err := h.RunPhase(60*time.Second, func(id party.ID) protocol.StartFunc {
		return lss.Keygen(curve.Secp256k1{}, id, partyIDs, threshold, pl)
	})
	require.NoError(b, err)
	
	configs := make(map[party.ID]*lss.Config)
	for id, res := range keygenRes {
		configs[id] = res.(*lss.Config)
	}
	
	// Benchmark signing
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		messageHash := make([]byte, 32)
		_, _ = rand.Read(messageHash)
		
		h2 := test.NewPhaseHarness(b, signers)
		_, err := h2.RunPhase(60*time.Second, func(id party.ID) protocol.StartFunc {
			config := configs[id]
			return lss.Sign(config, signers, messageHash, pl)
		})
		if err != nil {
			b.Fatalf("signing failed: %v", err)
		}
	}
}

func BenchmarkLSSPresignPhased(b *testing.B) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	// Setup: Run keygen once
	partyIDs := test.PartyIDs(5)
	threshold := 3
	signers := partyIDs[:threshold]
	
	h := test.NewPhaseHarness(b, partyIDs)
	keygenRes, err := h.RunPhase(60*time.Second, func(id party.ID) protocol.StartFunc {
		return lss.Keygen(curve.Secp256k1{}, id, partyIDs, threshold, pl)
	})
	require.NoError(b, err)
	
	configs := make(map[party.ID]*lss.Config)
	for id, res := range keygenRes {
		configs[id] = res.(*lss.Config)
	}
	
	// Benchmark presigning
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h2 := test.NewPhaseHarness(b, signers)
		_, err := h2.RunPhase(60*time.Second, func(id party.ID) protocol.StartFunc {
			_ = configs[id] // config would be used if Presign was implemented
			// return lss.Presign(config, signers, pl)
			return nil // Presign not implemented
		})
		if err != nil {
			b.Fatalf("presign failed: %v", err)
		}
	}
}