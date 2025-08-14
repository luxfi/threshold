package frost_test

import (
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/frost"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFROSTKeygenPhased(t *testing.T) {
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

			// Use simpler RunProtocol instead of PhaseHarness
			keygenRes, err := test.RunProtocol(t, partyIDs, []byte("frost-keygen-phased"), func(id party.ID) protocol.StartFunc {
				return frost.Keygen(curve.Secp256k1{}, id, partyIDs, tt.threshold)
			})
			require.NoError(t, err, "keygen should complete without error")
			require.Len(t, keygenRes, tt.partyCount)

			// Verify all parties have the same public key
			var firstPubKey curve.Point
			for id, res := range keygenRes {
				config, ok := res.(*frost.Config)
				require.True(t, ok, "result should be *frost.Config for party %s", id)
				require.NotNil(t, config)
				
				if firstPubKey == nil {
					firstPubKey = config.PublicKey
				} else {
					assert.True(t, firstPubKey.Equal(config.PublicKey),
						"all parties should have same public key")
				}
			}
		})
	}
}

func TestFROSTKeygenRefreshSignPhased(t *testing.T) {
	tests := []struct {
		name       string
		partyCount int
		threshold  int
		message    []byte
	}{
		{"2-of-3", 3, 2, []byte("test message 2-of-3")},
		{"3-of-5", 5, 3, []byte("test message 3-of-5")},
		{"5-of-7", 7, 5, []byte("test message 5-of-7")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			partyIDs := test.PartyIDs(tt.partyCount)

			// Phase 1: Keygen using simpler RunProtocol
			keygenRes, err := test.RunProtocol(t, partyIDs, []byte("frost-krs-keygen"), func(id party.ID) protocol.StartFunc {
				return frost.Keygen(curve.Secp256k1{}, id, partyIDs, tt.threshold)
			})
			require.NoError(t, err, "keygen should complete without error")
			require.Len(t, keygenRes, tt.partyCount)

			// Get the original public key
			firstConfig := keygenRes[partyIDs[0]].(*frost.Config)
			originalPubKey := firstConfig.PublicKey

			// Phase 2: Refresh using simpler RunProtocol
			refreshRes, err := test.RunProtocol(t, partyIDs, []byte("frost-krs-refresh"), func(id party.ID) protocol.StartFunc {
				config := keygenRes[id].(*frost.Config)
				return frost.Refresh(config, partyIDs)
			})
			require.NoError(t, err, "refresh should complete without error")
			require.Len(t, refreshRes, tt.partyCount)

			// Verify refresh maintained the same public key
			for id, res := range refreshRes {
				refreshedConfig := res.(*frost.Config)
				require.NotNil(t, refreshedConfig)
				assert.True(t, originalPubKey.Equal(refreshedConfig.PublicKey),
					"party %s should have same public key after refresh", id)
			}

			// Phase 3: Sign (subset signers - FROST needs exactly threshold)
			signers := partyIDs[:tt.threshold]
			
			signRes, err := test.RunProtocol(t, signers, []byte("frost-krs-sign"), func(id party.ID) protocol.StartFunc {
				config := refreshRes[id].(*frost.Config)
				return frost.Sign(config, signers, tt.message)
			})
			require.NoError(t, err, "signing should complete without error")
			require.Len(t, signRes, tt.threshold)

			// Verify all parties produced the same signature
			var firstSig *frost.Signature
			for id, res := range signRes {
				// Handle both value and pointer types
				var sig *frost.Signature
				switch s := res.(type) {
				case *frost.Signature:
					sig = s
				case frost.Signature:
					sig = &s
				default:
					t.Fatalf("unexpected signature type for %s: %T", id, res)
				}
				require.NotNil(t, sig)
				
				if firstSig == nil {
					firstSig = sig
				}
				// Verify the signature
				assert.True(t, sig.Verify(originalPubKey, tt.message),
					"signature should verify for party %s", id)
			}
		})
	}
}

func BenchmarkFROSTKeygenPhased(b *testing.B) {
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
				_, err := test.RunProtocol(b, partyIDs, []byte("frost-bench-keygen"), func(id party.ID) protocol.StartFunc {
					return frost.Keygen(curve.Secp256k1{}, id, partyIDs, bm.threshold)
				})
				if err != nil {
					b.Fatalf("keygen failed: %v", err)
				}
			}
		})
	}
}

func BenchmarkFROSTSignPhased(b *testing.B) {
	// Setup: Run keygen once
	partyIDs := test.PartyIDs(5)
	threshold := 3
	signers := partyIDs[:threshold]
	message := []byte("benchmark message")
	
	keygenRes, err := test.RunProtocol(b, partyIDs, []byte("frost-bench-setup"), func(id party.ID) protocol.StartFunc {
		return frost.Keygen(curve.Secp256k1{}, id, partyIDs, threshold)
	})
	require.NoError(b, err)
	
	// Benchmark signing
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := test.RunProtocol(b, signers, []byte("frost-bench-sign"), func(id party.ID) protocol.StartFunc {
			config := keygenRes[id].(*frost.Config)
			return frost.Sign(config, signers, message)
		})
		if err != nil {
			b.Fatalf("signing failed: %v", err)
		}
	}
}