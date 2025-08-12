package cmp_test

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
	"github.com/luxfi/threshold/protocols/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCMPKeygenPhased(t *testing.T) {
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
				return cmp.Keygen(curve.Secp256k1{}, id, partyIDs, tt.threshold, pl)
			})
			require.NoError(t, err, "keygen should complete without error")
			require.Len(t, keygenRes, tt.partyCount)

			// Verify all parties have the same public key
			var firstPubKey curve.Point
			for id, res := range keygenRes {
				config, ok := res.(*cmp.Config)
				require.True(t, ok, "result should be *cmp.Config for party %s", id)
				require.NotNil(t, config)
				require.NotNil(t, config.PublicPoint())
				
				if firstPubKey == nil {
					firstPubKey = config.PublicPoint()
				} else {
					assert.True(t, firstPubKey.Equal(config.PublicPoint()),
						"all parties should have same public key")
				}
			}
		})
	}
}

func TestCMPKeygenRefreshSignPhased(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	tests := []struct {
		name       string
		partyCount int
		threshold  int
	}{
		{"2-of-3", 3, 2},
		{"3-of-5", 5, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			partyIDs := test.PartyIDs(tt.partyCount)
			h := test.NewPhaseHarness(t, partyIDs)

			// Phase 1: Keygen
			keygenRes, err := h.RunPhase(60*time.Second, func(id party.ID) protocol.StartFunc {
				return cmp.Keygen(curve.Secp256k1{}, id, partyIDs, tt.threshold, pl)
			})
			require.NoError(t, err, "keygen should complete without error")
			require.Len(t, keygenRes, tt.partyCount)

			// Get the original public key
			firstConfig := keygenRes[partyIDs[0]].(*cmp.Config)
			originalPubKey := firstConfig.PublicPoint()

			// Phase 2: Refresh (new session)
			h.Reset() // Fresh network for clean separation
			refreshRes, err := h.RunPhase(60*time.Second, func(id party.ID) protocol.StartFunc {
				config := keygenRes[id].(*cmp.Config)
				return cmp.Refresh(config, pl)
			})
			require.NoError(t, err, "refresh should complete without error")
			require.Len(t, refreshRes, tt.partyCount)

			// Verify refresh maintained the same public key
			for id, res := range refreshRes {
				refreshedConfig := res.(*cmp.Config)
				require.NotNil(t, refreshedConfig)
				assert.True(t, originalPubKey.Equal(refreshedConfig.PublicPoint()),
					"party %s should have same public key after refresh", id)
			}

			// Phase 3: Sign (subset signers, new session)
			signers := partyIDs[:tt.threshold]
			h2 := test.NewPhaseHarness(t, signers) // New harness with just signers
			
			// Generate a random message hash
			messageHash := make([]byte, 32)
			_, _ = rand.Read(messageHash)
			
			signRes, err := h2.RunPhase(60*time.Second, func(id party.ID) protocol.StartFunc {
				config := refreshRes[id].(*cmp.Config)
				return cmp.Sign(config, signers, messageHash, pl)
			})
			require.NoError(t, err, "signing should complete without error")
			require.Len(t, signRes, tt.threshold)

			// Verify all parties produced valid signatures
			for id, res := range signRes {
				sig, ok := res.(*ecdsa.Signature)
				require.True(t, ok, "result should be *ecdsa.Signature for party %s", id)
				require.NotNil(t, sig)
				require.NotNil(t, sig.R)
				require.NotNil(t, sig.S)
				assert.False(t, sig.R.IsIdentity(), "R should be non-zero")
				assert.False(t, sig.S.IsZero(), "S should be non-zero")
			}
		})
	}
}

func TestCMPPresignPhased(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	partyIDs := test.PartyIDs(5)
	threshold := 3
	signers := partyIDs[:threshold]

	// Phase 1: Keygen
	h := test.NewPhaseHarness(t, partyIDs)
	keygenRes, err := h.RunPhase(60*time.Second, func(id party.ID) protocol.StartFunc {
		return cmp.Keygen(curve.Secp256k1{}, id, partyIDs, threshold, pl)
	})
	require.NoError(t, err, "keygen should complete without error")
	require.Len(t, keygenRes, 5)

	// Phase 2: Presign (new session, subset of parties)
	h2 := test.NewPhaseHarness(t, signers)
	presignRes, err := h2.RunPhase(60*time.Second, func(id party.ID) protocol.StartFunc {
		config := keygenRes[id].(*cmp.Config)
		return cmp.Presign(config, signers, pl)
	})
	require.NoError(t, err, "presign should complete without error")
	require.Len(t, presignRes, threshold)

	// Verify presignatures
	for id, res := range presignRes {
		presig, ok := res.(*ecdsa.PreSignature)
		require.True(t, ok, "result should be *ecdsa.PreSignature for party %s", id)
		require.NotNil(t, presig)
	}

	// Phase 3: Online signing with presignatures (new session)
	messageHash := make([]byte, 32)
	_, _ = rand.Read(messageHash)
	
	h3 := test.NewPhaseHarness(t, signers)
	onlineRes, err := h3.RunPhase(60*time.Second, func(id party.ID) protocol.StartFunc {
		config := keygenRes[id].(*cmp.Config)
		presig := presignRes[id].(*ecdsa.PreSignature)
		return cmp.PresignOnline(config, presig, messageHash, pl)
	})
	require.NoError(t, err, "online signing should complete without error")
	require.Len(t, onlineRes, threshold)

	// Verify signatures
	for id, res := range onlineRes {
		sig, ok := res.(*ecdsa.Signature)
		require.True(t, ok, "result should be *ecdsa.Signature for party %s", id)
		require.NotNil(t, sig)
		require.NotNil(t, sig.R)
		require.NotNil(t, sig.S)
	}
}

func BenchmarkCMPKeygenPhased(b *testing.B) {
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
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			partyIDs := test.PartyIDs(bm.partyCount)
			
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				h := test.NewPhaseHarness(b, partyIDs)
				
				_, err := h.RunPhase(60*time.Second, func(id party.ID) protocol.StartFunc {
					return cmp.Keygen(curve.Secp256k1{}, id, partyIDs, bm.threshold, pl)
				})
				if err != nil {
					b.Fatalf("keygen failed: %v", err)
				}
			}
		})
	}
}

func BenchmarkCMPSignPhased(b *testing.B) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	// Setup: Run keygen once
	partyIDs := test.PartyIDs(5)
	threshold := 3
	signers := partyIDs[:threshold]
	
	h := test.NewPhaseHarness(b, partyIDs)
	keygenRes, err := h.RunPhase(60*time.Second, func(id party.ID) protocol.StartFunc {
		return cmp.Keygen(curve.Secp256k1{}, id, partyIDs, threshold, pl)
	})
	require.NoError(b, err)
	
	// Benchmark signing
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		messageHash := make([]byte, 32)
		_, _ = rand.Read(messageHash)
		
		h2 := test.NewPhaseHarness(b, signers)
		_, err := h2.RunPhase(60*time.Second, func(id party.ID) protocol.StartFunc {
			config := keygenRes[id].(*cmp.Config)
			return cmp.Sign(config, signers, messageHash, pl)
		})
		if err != nil {
			b.Fatalf("signing failed: %v", err)
		}
	}
}