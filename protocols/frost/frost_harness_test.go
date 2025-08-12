package frost_test

import (
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/frost"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFROSTKeygen(t *testing.T) {
	tests := []test.ProtocolTest{
		{
			Name:       "2-of-3",
			PartyCount: 3,
			Threshold:  2,
			SessionID:  []byte("frost-keygen-2-of-3"),
			CreateStart: func(id party.ID, ids []party.ID, threshold int) protocol.StartFunc {
				return frost.Keygen(curve.Secp256k1{}, id, ids, threshold)
			},
			Validate: func(t *testing.T, results map[party.ID]interface{}) {
				// All parties should have configs
				require.Len(t, results, 3)
				
				// All configs should have the same public key
				var firstPubKey curve.Point
				for id, result := range results {
					config, ok := result.(*frost.Config)
					require.True(t, ok, "result should be *frost.Config for party %s", id)
					require.NotNil(t, config)
					
					if firstPubKey == nil {
						firstPubKey = config.PublicKey
					} else {
						assert.True(t, firstPubKey.Equal(config.PublicKey), 
							"all parties should have same public key")
					}
				}
			},
		},
		{
			Name:       "3-of-5",
			PartyCount: 5,
			Threshold:  3,
			SessionID:  []byte("frost-keygen-3-of-5"),
			CreateStart: func(id party.ID, ids []party.ID, threshold int) protocol.StartFunc {
				return frost.Keygen(curve.Secp256k1{}, id, ids, threshold)
			},
			Validate: func(t *testing.T, results map[party.ID]interface{}) {
				require.Len(t, results, 5)
				
				var firstPubKey curve.Point
				for id, result := range results {
					config, ok := result.(*frost.Config)
					require.True(t, ok, "result should be *frost.Config for party %s", id)
					require.NotNil(t, config)
					
					if firstPubKey == nil {
						firstPubKey = config.PublicKey
					} else {
						assert.True(t, firstPubKey.Equal(config.PublicKey))
					}
				}
			},
		},
		{
			Name:       "5-of-7",
			PartyCount: 7,
			Threshold:  5,
			SessionID:  []byte("frost-keygen-5-of-7"),
			CreateStart: func(id party.ID, ids []party.ID, threshold int) protocol.StartFunc {
				return frost.Keygen(curve.Secp256k1{}, id, ids, threshold)
			},
			Validate: func(t *testing.T, results map[party.ID]interface{}) {
				require.Len(t, results, 7)
				
				var firstPubKey curve.Point
				for id, result := range results {
					config, ok := result.(*frost.Config)
					require.True(t, ok, "result should be *frost.Config for party %s", id)
					require.NotNil(t, config)
					
					if firstPubKey == nil {
						firstPubKey = config.PublicKey
					} else {
						assert.True(t, firstPubKey.Equal(config.PublicKey))
					}
				}
			},
		},
	}
	
	test.RunMultipleProtocolTests(t, tests)
}

func TestFROSTKeygenAndSign(t *testing.T) {
	tests := []test.KeygenAndSign{
		{
			Name:       "2-of-3 signature",
			PartyCount: 3,
			Threshold:  2,
			Message:    []byte("test message for 2-of-3"),
			CreateKeygen: func(id party.ID, ids []party.ID, threshold int) protocol.StartFunc {
				return frost.Keygen(curve.Secp256k1{}, id, ids, threshold)
			},
			CreateSign: func(config interface{}, signers []party.ID, message []byte) protocol.StartFunc {
				frostConfig := config.(*frost.Config)
				return frost.Sign(frostConfig, signers, message)
			},
			ValidateSign: func(t *testing.T, config interface{}, signature interface{}, message []byte) {
				frostConfig := config.(*frost.Config)
				sig := signature.(*frost.Signature)
				require.NotNil(t, sig)
				assert.True(t, sig.Verify(frostConfig.PublicKey, message), "signature should verify")
			},
		},
		{
			Name:       "3-of-5 signature",
			PartyCount: 5,
			Threshold:  3,
			Message:    []byte("test message for 3-of-5"),
			CreateKeygen: func(id party.ID, ids []party.ID, threshold int) protocol.StartFunc {
				return frost.Keygen(curve.Secp256k1{}, id, ids, threshold)
			},
			CreateSign: func(config interface{}, signers []party.ID, message []byte) protocol.StartFunc {
				frostConfig := config.(*frost.Config)
				return frost.Sign(frostConfig, signers, message)
			},
			ValidateSign: func(t *testing.T, config interface{}, signature interface{}, message []byte) {
				frostConfig := config.(*frost.Config)
				sig := signature.(*frost.Signature)
				require.NotNil(t, sig)
				assert.True(t, sig.Verify(frostConfig.PublicKey, message), "signature should verify")
			},
		},
		{
			Name:       "5-of-7 signature",
			PartyCount: 7,
			Threshold:  5,
			Message:    []byte("test message for 5-of-7"),
			CreateKeygen: func(id party.ID, ids []party.ID, threshold int) protocol.StartFunc {
				return frost.Keygen(curve.Secp256k1{}, id, ids, threshold)
			},
			CreateSign: func(config interface{}, signers []party.ID, message []byte) protocol.StartFunc {
				frostConfig := config.(*frost.Config)
				return frost.Sign(frostConfig, signers, message)
			},
			ValidateSign: func(t *testing.T, config interface{}, signature interface{}, message []byte) {
				frostConfig := config.(*frost.Config)
				sig := signature.(*frost.Signature)
				require.NotNil(t, sig)
				assert.True(t, sig.Verify(frostConfig.PublicKey, message), "signature should verify")
			},
		},
	}
	
	for _, test := range tests {
		test.Run(t)
	}
}

func TestFROSTRefresh(t *testing.T) {
	// First run keygen
	partyIDs := test.PartyIDs(5)
	threshold := 3
	
	keygenResults, err := test.RunProtocol(t, partyIDs, nil, func(id party.ID) protocol.StartFunc {
		return frost.Keygen(curve.Secp256k1{}, id, partyIDs, threshold)
	})
	require.NoError(t, err)
	require.Len(t, keygenResults, 5)
	
	// Get the original public key
	firstConfig := keygenResults[partyIDs[0]].(*frost.Config)
	originalPubKey := firstConfig.PublicKey
	
	// Run refresh with a new session ID
	refreshResults, err := test.RunProtocol(t, partyIDs, nil, func(id party.ID) protocol.StartFunc {
		config := keygenResults[id].(*frost.Config)
		return frost.Refresh(config, partyIDs)
	})
	require.NoError(t, err)
	require.Len(t, refreshResults, 5)
	
	// Verify refresh maintained the same public key
	for id, result := range refreshResults {
		refreshedConfig := result.(*frost.Config)
		require.NotNil(t, refreshedConfig)
		assert.True(t, originalPubKey.Equal(refreshedConfig.PublicKey), 
			"party %s should have same public key after refresh", id)
	}
}

func BenchmarkFROSTKeygen(b *testing.B) {
	benchmarks := []test.ProtocolBenchmark{
		{
			Name:       "2-of-3",
			PartyCount: 3,
			Threshold:  2,
			CreateStart: func(id party.ID, ids []party.ID, threshold int) protocol.StartFunc {
				return frost.Keygen(curve.Secp256k1{}, id, ids, threshold)
			},
		},
		{
			Name:       "3-of-5",
			PartyCount: 5,
			Threshold:  3,
			CreateStart: func(id party.ID, ids []party.ID, threshold int) protocol.StartFunc {
				return frost.Keygen(curve.Secp256k1{}, id, ids, threshold)
			},
		},
		{
			Name:       "5-of-7",
			PartyCount: 7,
			Threshold:  5,
			CreateStart: func(id party.ID, ids []party.ID, threshold int) protocol.StartFunc {
				return frost.Keygen(curve.Secp256k1{}, id, ids, threshold)
			},
		},
	}
	
	test.RunProtocolBenchmarks(b, benchmarks)
}

func BenchmarkFROSTSign(b *testing.B) {
	// Setup: Run keygen once
	partyIDs := test.PartyIDs(5)
	threshold := 3
	signers := partyIDs[:threshold]
	message := []byte("benchmark message")
	
	keygenResults, err := test.RunProtocol(b, partyIDs, nil, func(id party.ID) protocol.StartFunc {
		return frost.Keygen(curve.Secp256k1{}, id, partyIDs, threshold)
	})
	require.NoError(b, err)
	
	// Benchmark signing
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		signResults, err := test.RunProtocol(b, signers, nil, func(id party.ID) protocol.StartFunc {
			config := keygenResults[id].(*frost.Config)
			return frost.Sign(config, signers, message)
		})
		require.NoError(b, err)
		require.Len(b, signResults, threshold)
	}
}

// TestFROSTWithPool tests FROST with a worker pool
func TestFROSTWithPool(t *testing.T) {
	pl := pool.NewPool(4) // Use 4 workers
	defer pl.TearDown()
	
	partyIDs := test.PartyIDs(5)
	threshold := 3
	
	// Create keygen with pool
	keygenResults, err := test.RunProtocol(t, partyIDs, nil, func(id party.ID) protocol.StartFunc {
		// Note: FROST doesn't use pool in its current implementation
		// This is here to show how it would be integrated if needed
		return frost.Keygen(curve.Secp256k1{}, id, partyIDs, threshold)
	})
	require.NoError(t, err)
	require.Len(t, keygenResults, 5)
	
	// Verify all configs have the same public key
	var firstPubKey curve.Point
	for _, result := range keygenResults {
		config := result.(*frost.Config)
		if firstPubKey == nil {
			firstPubKey = config.PublicKey
		} else {
			assert.True(t, firstPubKey.Equal(config.PublicKey))
		}
	}
}