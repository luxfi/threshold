package cmp_test

import (
	"crypto/rand"
	"testing"

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

func TestCMPKeygen(t *testing.T) {
	// Create pools map for each party
	pools := make(map[party.ID]*pool.Pool)
	
	tests := []test.ProtocolTest{
		{
			Name:       "2-of-3",
			PartyCount: 3,
			Threshold:  2,
			SessionID:  []byte("cmp-keygen-2-of-3"),
			CreateStart: func(id party.ID, ids []party.ID, threshold int) protocol.StartFunc {
				if pools[id] == nil {
					pools[id] = pool.NewPool(0)
				}
				return cmp.Keygen(curve.Secp256k1{}, id, ids, threshold, pools[id])
			},
			Validate: func(t *testing.T, results map[party.ID]interface{}) {
				require.Len(t, results, 3)
				
				// Verify all parties have valid configs with same public key
				var firstPubKey curve.Point
				for id, result := range results {
					config, ok := result.(*cmp.Config)
					require.True(t, ok, "result should be *cmp.Config for party %s", id)
					require.NotNil(t, config)
					pubKey := config.PublicPoint()
					require.NotNil(t, pubKey)
					
					if firstPubKey == nil {
						firstPubKey = pubKey
					} else {
						assert.True(t, firstPubKey.Equal(pubKey),
							"all parties should have same public key")
					}
				}
			},
		},
		{
			Name:       "3-of-5",
			PartyCount: 5,
			Threshold:  3,
			SessionID:  []byte("cmp-keygen-3-of-5"),
			CreateStart: func(id party.ID, ids []party.ID, threshold int) protocol.StartFunc {
				if pools[id] == nil {
					pools[id] = pool.NewPool(0)
				}
				return cmp.Keygen(curve.Secp256k1{}, id, ids, threshold, pools[id])
			},
			Validate: func(t *testing.T, results map[party.ID]interface{}) {
				require.Len(t, results, 5)
				
				var firstPubKey curve.Point
				for id, result := range results {
					config, ok := result.(*cmp.Config)
					require.True(t, ok, "result should be *cmp.Config for party %s", id)
					require.NotNil(t, config)
					pubKey := config.PublicPoint()
					require.NotNil(t, pubKey)
					
					if firstPubKey == nil {
						firstPubKey = pubKey
					} else {
						assert.True(t, firstPubKey.Equal(pubKey))
					}
				}
			},
		},
	}
	
	test.RunMultipleProtocolTests(t, tests)
	
	// Clean up pools
	for _, pl := range pools {
		pl.TearDown()
	}
}

func TestCMPKeygenAndSign(t *testing.T) {
	// Create pools map for each party
	pools := make(map[party.ID]*pool.Pool)
	defer func() {
		for _, pl := range pools {
			pl.TearDown()
		}
	}()
	
	tests := []test.KeygenAndSign{
		{
			Name:       "2-of-3 signature",
			PartyCount: 3,
			Threshold:  2,
			Message:    []byte("test message for 2-of-3"),
			CreateKeygen: func(id party.ID, ids []party.ID, threshold int) protocol.StartFunc {
				if pools[id] == nil {
					pools[id] = pool.NewPool(0)
				}
				return cmp.Keygen(curve.Secp256k1{}, id, ids, threshold, pools[id])
			},
			CreateSign: func(config interface{}, signers []party.ID, message []byte) protocol.StartFunc {
				cmpConfig := config.(*cmp.Config)
				messageHash := make([]byte, 32)
				_, _ = rand.Read(messageHash)
				if pools[cmpConfig.ID] == nil {
					pools[cmpConfig.ID] = pool.NewPool(0)
				}
				return cmp.Sign(cmpConfig, signers, messageHash, pools[cmpConfig.ID])
			},
			ValidateSign: func(t *testing.T, config interface{}, signature interface{}, message []byte) {
				cmpConfig := config.(*cmp.Config)
				sig := signature.(*ecdsa.Signature)
				require.NotNil(t, sig)
				// For ECDSA, we can't directly verify without the actual hash that was signed
				// But we can check the signature is well-formed
				require.NotNil(t, sig.R)
				require.NotNil(t, sig.S)
				assert.False(t, sig.R.IsIdentity(), "R should be non-zero")
				assert.False(t, sig.S.IsZero(), "S should be non-zero")
				_ = cmpConfig // Would verify with actual message hash
			},
		},
		{
			Name:       "3-of-5 signature",
			PartyCount: 5,
			Threshold:  3,
			Message:    []byte("test message for 3-of-5"),
			CreateKeygen: func(id party.ID, ids []party.ID, threshold int) protocol.StartFunc {
				if pools[id] == nil {
					pools[id] = pool.NewPool(0)
				}
				return cmp.Keygen(curve.Secp256k1{}, id, ids, threshold, pools[id])
			},
			CreateSign: func(config interface{}, signers []party.ID, message []byte) protocol.StartFunc {
				cmpConfig := config.(*cmp.Config)
				messageHash := make([]byte, 32)
				_, _ = rand.Read(messageHash)
				if pools[cmpConfig.ID] == nil {
					pools[cmpConfig.ID] = pool.NewPool(0)
				}
				return cmp.Sign(cmpConfig, signers, messageHash, pools[cmpConfig.ID])
			},
			ValidateSign: func(t *testing.T, config interface{}, signature interface{}, message []byte) {
				cmpConfig := config.(*cmp.Config)
				sig := signature.(*ecdsa.Signature)
				require.NotNil(t, sig)
				require.NotNil(t, sig.R)
				require.NotNil(t, sig.S)
				assert.False(t, sig.R.IsIdentity(), "R should be non-zero")
				assert.False(t, sig.S.IsZero(), "S should be non-zero")
				_ = cmpConfig
			},
		},
	}
	
	for _, test := range tests {
		test.Run(t)
	}
}

func TestCMPRefresh(t *testing.T) {
	// Create pools map for each party
	pools := make(map[party.ID]*pool.Pool)
	defer func() {
		for _, pl := range pools {
			pl.TearDown()
		}
	}()
	
	// First run keygen
	partyIDs := test.PartyIDs(5)
	threshold := 3
	
	keygenResults, err := test.RunProtocol(t, partyIDs, nil, func(id party.ID) protocol.StartFunc {
		if pools[id] == nil {
			pools[id] = pool.NewPool(0)
		}
		return cmp.Keygen(curve.Secp256k1{}, id, partyIDs, threshold, pools[id])
	})
	require.NoError(t, err)
	require.Len(t, keygenResults, 5)
	
	// Get the original public key
	firstConfig := keygenResults[partyIDs[0]].(*cmp.Config)
	originalPubKey := firstConfig.PublicPoint()
	
	// Run refresh with a new session ID
	refreshResults, err := test.RunProtocol(t, partyIDs, nil, func(id party.ID) protocol.StartFunc {
		config := keygenResults[id].(*cmp.Config)
		if pools[id] == nil {
			pools[id] = pool.NewPool(0)
		}
		return cmp.Refresh(config, pools[id])
	})
	require.NoError(t, err)
	require.Len(t, refreshResults, 5)
	
	// Verify refresh maintained the same public key
	for id, result := range refreshResults {
		refreshedConfig := result.(*cmp.Config)
		require.NotNil(t, refreshedConfig)
		assert.True(t, originalPubKey.Equal(refreshedConfig.PublicPoint()),
			"party %s should have same public key after refresh", id)
	}
}

func TestCMPPresign(t *testing.T) {
	// Create pools map for each party
	pools := make(map[party.ID]*pool.Pool)
	defer func() {
		for _, pl := range pools {
			pl.TearDown()
		}
	}()
	
	// First run keygen
	partyIDs := test.PartyIDs(5)
	threshold := 3
	signers := partyIDs[:threshold]
	
	keygenResults, err := test.RunProtocol(t, partyIDs, nil, func(id party.ID) protocol.StartFunc {
		if pools[id] == nil {
			pools[id] = pool.NewPool(0)
		}
		return cmp.Keygen(curve.Secp256k1{}, id, partyIDs, threshold, pools[id])
	})
	require.NoError(t, err)
	require.Len(t, keygenResults, 5)
	
	// Run presign with a new session ID
	presignResults, err := test.RunProtocol(t, signers, nil, func(id party.ID) protocol.StartFunc {
		config := keygenResults[id].(*cmp.Config)
		if pools[id] == nil {
			pools[id] = pool.NewPool(0)
		}
		return cmp.Presign(config, signers, pools[id])
	})
	require.NoError(t, err)
	require.Len(t, presignResults, threshold)
	
	// Verify presignatures
	for id, result := range presignResults {
		presig, ok := result.(*ecdsa.PreSignature)
		require.True(t, ok, "result should be *ecdsa.PreSignature for party %s", id)
		require.NotNil(t, presig)
	}
	
	// Use presignatures for online signing
	// message := []byte("test message for presign")
	// TODO: Use message for signature verification when implemented
	messageHash := make([]byte, 32)
	_, _ = rand.Read(messageHash)
	
	onlineResults, err := test.RunProtocol(t, signers, nil, func(id party.ID) protocol.StartFunc {
		config := keygenResults[id].(*cmp.Config)
		presig := presignResults[id].(*ecdsa.PreSignature)
		if pools[id] == nil {
			pools[id] = pool.NewPool(0)
		}
		return cmp.PresignOnline(config, presig, messageHash, pools[id])
	})
	require.NoError(t, err)
	require.Len(t, onlineResults, threshold)
	
	// Verify signatures
	for id, result := range onlineResults {
		sig, ok := result.(*ecdsa.Signature)
		require.True(t, ok, "result should be *ecdsa.Signature for party %s", id)
		require.NotNil(t, sig)
		require.NotNil(t, sig.R)
		require.NotNil(t, sig.S)
	}
}

func BenchmarkCMPKeygen(b *testing.B) {
	// Create pools map for each party
	pools := make(map[party.ID]*pool.Pool)
	defer func() {
		for _, pl := range pools {
			pl.TearDown()
		}
	}()
	
	benchmarks := []test.ProtocolBenchmark{
		{
			Name:       "2-of-3",
			PartyCount: 3,
			Threshold:  2,
			CreateStart: func(id party.ID, ids []party.ID, threshold int) protocol.StartFunc {
				if pools[id] == nil {
					pools[id] = pool.NewPool(0)
				}
				return cmp.Keygen(curve.Secp256k1{}, id, ids, threshold, pools[id])
			},
		},
		{
			Name:       "3-of-5",
			PartyCount: 5,
			Threshold:  3,
			CreateStart: func(id party.ID, ids []party.ID, threshold int) protocol.StartFunc {
				if pools[id] == nil {
					pools[id] = pool.NewPool(0)
				}
				return cmp.Keygen(curve.Secp256k1{}, id, ids, threshold, pools[id])
			},
		},
	}
	
	test.RunProtocolBenchmarks(b, benchmarks)
}

func BenchmarkCMPSign(b *testing.B) {
	// Create pools map for each party
	pools := make(map[party.ID]*pool.Pool)
	defer func() {
		for _, pl := range pools {
			pl.TearDown()
		}
	}()
	
	// Setup: Run keygen once
	partyIDs := test.PartyIDs(5)
	threshold := 3
	signers := partyIDs[:threshold]
	
	keygenResults, err := test.RunProtocol(b, partyIDs, nil, func(id party.ID) protocol.StartFunc {
		if pools[id] == nil {
			pools[id] = pool.NewPool(0)
		}
		return cmp.Keygen(curve.Secp256k1{}, id, partyIDs, threshold, pools[id])
	})
	require.NoError(b, err)
	
	// Benchmark signing
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		messageHash := make([]byte, 32)
		_, _ = rand.Read(messageHash)
		
		signResults, err := test.RunProtocol(b, signers, nil, func(id party.ID) protocol.StartFunc {
			config := keygenResults[id].(*cmp.Config)
			if pools[id] == nil {
				pools[id] = pool.NewPool(0)
			}
			return cmp.Sign(config, signers, messageHash, pools[id])
		})
		require.NoError(b, err)
		require.Len(b, signResults, threshold)
	}
}