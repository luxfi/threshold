package adapters_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/unified/adapters"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestChainCompatibilityMatrix tests all chain adapters with their supported signature types
func TestChainCompatibilityMatrix(t *testing.T) {
	tests := []struct {
		chain          string
		signatureTypes []adapters.SignatureType
		testData       interface{}
	}{
		{
			chain:          "xrpl",
			signatureTypes: []adapters.SignatureType{adapters.SignatureECDSA, adapters.SignatureEdDSA},
			testData:       []byte("test xrpl transaction"),
		},
		{
			chain:          "ethereum",
			signatureTypes: []adapters.SignatureType{adapters.SignatureECDSA},
			testData: &adapters.LegacyTransaction{
				Nonce:    1,
				GasPrice: big.NewInt(20000000000),
				GasLimit: 21000,
				Value:    big.NewInt(1000000000000000000),
			},
		},
		{
			chain:          "bitcoin",
			signatureTypes: []adapters.SignatureType{adapters.SignatureECDSA, adapters.SignatureSchnorr},
			testData: &adapters.LegacyBitcoinTx{
				Version:  2,
				LockTime: 0,
				SigHash:  adapters.SigHashAll,
			},
		},
		{
			chain:          "solana",
			signatureTypes: []adapters.SignatureType{adapters.SignatureEdDSA},
			testData: &adapters.SolanaMessage{
				NumRequiredSignatures: 1,
				RecentBlockhash:      [32]byte{1, 2, 3},
			},
		},
	}

	for _, tt := range tests {
		for _, sigType := range tt.signatureTypes {
			testName := fmt.Sprintf("%s_%v", tt.chain, sigType)
			t.Run(testName, func(t *testing.T) {
				testChainAdapter(t, tt.chain, sigType, tt.testData)
			})
		}
	}
}

func testChainAdapter(t *testing.T, chain string, sigType adapters.SignatureType, testData interface{}) {
	// Create adapter
	factory := &adapters.AdapterFactory{}
	adapter := factory.NewAdapter(chain, sigType)
	require.NotNil(t, adapter, "adapter should be created for %s", chain)

	// Test digest computation
	digest, err := adapter.Digest(testData)
	require.NoError(t, err)
	assert.NotEmpty(t, digest)
	assert.Len(t, digest, 32, "digest should be 32 bytes")

	// Create mock shares
	shares := createMockShares(t, sigType, 3, 2)

	// Test partial signing
	var partialSigs []adapters.PartialSig
	for _, share := range shares[:2] { // Use threshold number
		partial, err := adapter.SignEC(digest, share)
		require.NoError(t, err)
		assert.NotNil(t, partial)
		partialSigs = append(partialSigs, partial)
	}

	// Test aggregation
	fullSig, err := adapter.AggregateEC(partialSigs)
	require.NoError(t, err)
	assert.NotNil(t, fullSig)

	// Test encoding
	encoded, err := adapter.Encode(fullSig)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)

	// Verify encoding format based on chain
	verifyEncodingFormat(t, chain, sigType, encoded)
}

// TestXRPLSpecificFeatures tests XRPL-specific requirements
func TestXRPLSpecificFeatures(t *testing.T) {
	t.Run("STX_SMT_Prefixes", func(t *testing.T) {
		// Test single-signing prefix
		xrplSingle := adapters.NewXRPLAdapter(adapters.SignatureECDSA, false)
		txBlob := []byte("test transaction")
		
		digestSingle, err := xrplSingle.Digest(txBlob)
		require.NoError(t, err)
		
		// Test multi-signing prefix
		xrplMulti := adapters.NewXRPLAdapter(adapters.SignatureECDSA, true)
		digestMulti, err := xrplMulti.Digest(txBlob)
		require.NoError(t, err)
		
		// Digests should be different due to different prefixes
		assert.NotEqual(t, digestSingle, digestMulti)
	})

	t.Run("Ed25519_Prefix", func(t *testing.T) {
		xrpl := adapters.NewXRPLAdapter(adapters.SignatureEdDSA, false)
		
		// Create mock Ed25519 public key
		pubKey := curve.Edwards25519{}.NewGenerator()
		formatted := xrpl.FormatPublicKey(pubKey)
		
		// Should start with ED prefix
		decoded, err := hex.DecodeString(formatted)
		require.NoError(t, err)
		assert.Equal(t, byte(0xED), decoded[0])
	})

	t.Run("Low_S_Normalization", func(t *testing.T) {
		xrpl := adapters.NewXRPLAdapter(adapters.SignatureECDSA, false)
		
		// Create high S value
		group := curve.Secp256k1{}
		order := group.Order()
		halfOrder := new(big.Int).Div(order, big.NewInt(2))
		highS := new(big.Int).Add(halfOrder, big.NewInt(100))
		
		// Create partial signature with high S
		partial := &adapters.ECDSAPartialSig{
			PartyID: "test",
			R:       group.NewScalar(),
			S:       group.NewScalar().SetNat(highS.MarshalBinary()),
		}
		
		// Aggregate should normalize to low S
		full, err := xrpl.AggregateEC([]adapters.PartialSig{partial})
		require.NoError(t, err)
		
		ecdsaSig := full.(*adapters.ECDSAFullSig)
		sInt := new(big.Int).SetBytes(ecdsaSig.S.MarshalBinary())
		assert.True(t, sInt.Cmp(halfOrder) <= 0, "S should be normalized to low value")
	})
}

// TestEthereumSpecificFeatures tests Ethereum-specific requirements
func TestEthereumSpecificFeatures(t *testing.T) {
	t.Run("EIP155_ChainID", func(t *testing.T) {
		eth := adapters.NewEthereumAdapter()
		
		// Test different chain IDs
		chainIDs := []*big.Int{
			big.NewInt(1),    // Mainnet
			big.NewInt(5),    // Goerli
			big.NewInt(137),  // Polygon
			big.NewInt(42161), // Arbitrum
		}
		
		for _, chainID := range chainIDs {
			eth.SetChainID(chainID)
			
			tx := &adapters.LegacyTransaction{
				Nonce:    1,
				GasPrice: big.NewInt(20000000000),
				GasLimit: 21000,
			}
			
			digest, err := eth.Digest(tx)
			require.NoError(t, err)
			assert.NotEmpty(t, digest)
		}
	})

	t.Run("TypedTransactions", func(t *testing.T) {
		eth := adapters.NewEthereumAdapter()
		
		// Test EIP-1559 transaction
		eip1559 := &adapters.EIP1559Transaction{
			ChainID:              big.NewInt(1),
			Nonce:                1,
			MaxPriorityFeePerGas: big.NewInt(1000000000),
			MaxFeePerGas:         big.NewInt(30000000000),
			GasLimit:             21000,
		}
		
		digest1559, err := eth.Digest(eip1559)
		require.NoError(t, err)
		assert.Len(t, digest1559, 32)
		
		// Test EIP-4844 blob transaction
		eip4844 := &adapters.EIP4844Transaction{
			ChainID:              big.NewInt(1),
			MaxFeePerBlobGas:     big.NewInt(1000000000),
			BlobVersionedHashes:  [][32]byte{{1}, {2}},
		}
		
		digest4844, err := eth.Digest(eip4844)
		require.NoError(t, err)
		assert.Len(t, digest4844, 32)
	})
}

// TestBitcoinTaprootFeatures tests Bitcoin Taproot-specific features
func TestBitcoinTaprootFeatures(t *testing.T) {
	t.Run("BIP340_Schnorr", func(t *testing.T) {
		btc := adapters.NewBitcoinAdapter(adapters.SignatureSchnorr)
		
		// Create Taproot transaction
		taproot := &adapters.TaprootTx{
			SegwitTx: adapters.SegwitTx{
				Version:  2,
				Amount:   100000000,
				Sequence: 0xfffffffd,
				SigHash:  adapters.SigHashDefault,
			},
			ScriptPath: false, // Key path spend
		}
		
		digest, err := btc.Digest(taproot)
		require.NoError(t, err)
		assert.Len(t, digest, 32)
		
		// Test with tweak
		tweak := make([]byte, 32)
		rand.Read(tweak)
		btc.SetTaprootTweak(tweak)
		
		digestTweaked, err := btc.Digest(taproot)
		require.NoError(t, err)
		assert.NotEqual(t, digest, digestTweaked)
	})

	t.Run("ScriptPath_Spending", func(t *testing.T) {
		btc := adapters.NewBitcoinAdapter(adapters.SignatureSchnorr)
		
		// Create script path spend
		taproot := &adapters.TaprootTx{
			ScriptPath:   true,
			TapScript:    []byte{0x51}, // OP_1
			ControlBlock: make([]byte, 33),
		}
		
		digest, err := btc.Digest(taproot)
		require.NoError(t, err)
		assert.NotEmpty(t, digest)
	})
}

// TestSolanaFeatures tests Solana-specific features
func TestSolanaFeatures(t *testing.T) {
	t.Run("Ed25519_Only", func(t *testing.T) {
		sol := adapters.NewSolanaAdapter()
		
		// Solana only supports Ed25519
		config := &adapters.UnifiedConfig{
			SignatureScheme: adapters.SignatureEdDSA,
			Group:          curve.Edwards25519{},
		}
		
		err := sol.ValidateConfig(config)
		require.NoError(t, err)
		
		// Should reject ECDSA
		config.SignatureScheme = adapters.SignatureECDSA
		err = sol.ValidateConfig(config)
		assert.Error(t, err)
	})

	t.Run("CompactArray_Encoding", func(t *testing.T) {
		sol := adapters.NewSolanaAdapter()
		
		msg := &adapters.SolanaMessage{
			NumRequiredSignatures: 2,
			AccountKeys:          [][32]byte{{1}, {2}, {3}},
			Instructions: []*adapters.SolanaInstruction{
				{
					ProgramIDIndex: 0,
					AccountIndices: []byte{1, 2},
					Data:          []byte{0x02, 0x00, 0x00, 0x00},
				},
			},
		}
		
		digest, err := sol.Digest(msg)
		require.NoError(t, err)
		assert.NotEmpty(t, digest)
	})

	t.Run("PDA_Derivation", func(t *testing.T) {
		sol := adapters.NewSolanaAdapter()
		
		programID := [32]byte{1, 2, 3}
		seeds := [][]byte{
			[]byte("threshold"),
			[]byte("wallet"),
		}
		
		pda, bump, err := sol.ComputeProgramDerivedAddress(programID, seeds)
		require.NoError(t, err)
		assert.NotEqual(t, [32]byte{}, pda)
		assert.Greater(t, bump, byte(0))
	})
}

// TestRingtailPQAdapter tests post-quantum Ringtail adapter
func TestRingtailPQAdapter(t *testing.T) {
	t.Run("SecurityLevels", func(t *testing.T) {
		levels := []int{128, 192, 256}
		
		for _, level := range levels {
			ringtail := adapters.NewRingtailAdapter(level, 100)
			
			// Test DKG
			parties := []party.ID{"alice", "bob", "charlie"}
			pubKey, shares, err := ringtail.RingtailDKG(parties, 2)
			require.NoError(t, err)
			assert.NotNil(t, pubKey)
			assert.Len(t, shares, 3)
		}
	})

	t.Run("OfflinePreprocessing", func(t *testing.T) {
		ringtail := adapters.NewRingtailAdapter(128, 10)
		
		// Setup
		parties := []party.ID{"alice", "bob", "charlie"}
		_, shares, err := ringtail.RingtailDKG(parties, 2)
		require.NoError(t, err)
		
		// Generate offline preprocessing
		err = ringtail.PreprocessOffline(5)
		require.NoError(t, err)
		
		// Use preprocessing for signing
		message := []byte("test message")
		digest, _ := ringtail.Digest(message)
		
		share := adapters.Share{
			ID:    parties[0],
			Value: shares[parties[0]],
		}
		
		partial, err := ringtail.SignEC(digest, share)
		require.NoError(t, err)
		assert.NotNil(t, partial)
	})

	t.Run("LargeScale", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping large scale test in short mode")
		}
		
		// Test with 100 parties as mentioned in paper
		ringtail := adapters.NewRingtailAdapter(128, 100)
		
		parties := make([]party.ID, 100)
		for i := 0; i < 100; i++ {
			parties[i] = party.ID(fmt.Sprintf("party_%d", i))
		}
		
		// 67-of-100 threshold
		_, shares, err := ringtail.RingtailDKG(parties, 67)
		require.NoError(t, err)
		assert.Len(t, shares, 100)
	})

	t.Run("SignatureSize", func(t *testing.T) {
		ringtail := adapters.NewRingtailAdapter(128, 10)
		
		// Expected ~13.4KB for 128-bit security
		params := adapters.GetRecommendedParams(128, 10)
		assert.Equal(t, 13400, params.SignatureSize)
		
		// Create mock signature
		fullSig := &adapters.RingtailFullSig{
			Signature: make([]int64, params.N),
			Size:     params.SignatureSize,
		}
		
		encoded, err := ringtail.Encode(fullSig)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(encoded), params.SignatureSize)
	})
}

// Benchmark tests
func BenchmarkAdapters(b *testing.B) {
	benchmarks := []struct {
		name    string
		adapter adapters.SignerAdapter
		sigType adapters.SignatureType
	}{
		{"XRPL_ECDSA", adapters.NewXRPLAdapter(adapters.SignatureECDSA, false), adapters.SignatureECDSA},
		{"XRPL_EdDSA", adapters.NewXRPLAdapter(adapters.SignatureEdDSA, false), adapters.SignatureEdDSA},
		{"Ethereum", adapters.NewEthereumAdapter(), adapters.SignatureECDSA},
		{"Bitcoin_ECDSA", adapters.NewBitcoinAdapter(adapters.SignatureECDSA), adapters.SignatureECDSA},
		{"Bitcoin_Schnorr", adapters.NewBitcoinAdapter(adapters.SignatureSchnorr), adapters.SignatureSchnorr},
		{"Solana", adapters.NewSolanaAdapter(), adapters.SignatureEdDSA},
		{"Ringtail_128", adapters.NewRingtailAdapter(128, 10), adapters.SignatureRingtail},
	}

	for _, bench := range benchmarks {
		b.Run(bench.name+"_Digest", func(b *testing.B) {
			data := make([]byte, 256)
			rand.Read(data)
			
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = bench.adapter.Digest(data)
			}
		})

		b.Run(bench.name+"_Sign", func(b *testing.B) {
			digest := make([]byte, 32)
			rand.Read(digest)
			
			share := createMockShares(b, bench.sigType, 1, 1)[0]
			
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = bench.adapter.SignEC(digest, share)
			}
		})

		b.Run(bench.name+"_Aggregate", func(b *testing.B) {
			shares := createMockShares(b, bench.sigType, 5, 3)
			digest := make([]byte, 32)
			
			var partials []adapters.PartialSig
			for _, share := range shares[:3] {
				partial, _ := bench.adapter.SignEC(digest, share)
				partials = append(partials, partial)
			}
			
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = bench.adapter.AggregateEC(partials)
			}
		})
	}
}

// Helper functions

func createMockShares(t testing.TB, sigType adapters.SignatureType, n, threshold int) []adapters.Share {
	var shares []adapters.Share
	
	for i := 0; i < n; i++ {
		var value interface{}
		
		switch sigType {
		case adapters.SignatureECDSA, adapters.SignatureSchnorr:
			value = curve.Secp256k1{}.NewScalar()
		case adapters.SignatureEdDSA:
			value = curve.Edwards25519{}.NewScalar()
		case adapters.SignatureRingtail:
			// Mock Ringtail share
			value = &adapters.RingtailSecretShare{
				PartyID: party.ID(fmt.Sprintf("party_%d", i)),
				S:       make([]int64, 512),
				E:       make([]int64, 512),
				Index:   i,
			}
		default:
			value = curve.Secp256k1{}.NewScalar()
		}
		
		shares = append(shares, adapters.Share{
			ID:    party.ID(fmt.Sprintf("party_%d", i)),
			Value: value,
			Index: i,
		})
	}
	
	return shares
}

func verifyEncodingFormat(t *testing.T, chain string, sigType adapters.SignatureType, encoded []byte) {
	switch chain {
	case "xrpl":
		if sigType == adapters.SignatureECDSA {
			// DER format check
			assert.Equal(t, byte(0x30), encoded[0], "ECDSA should be DER encoded")
		} else {
			// Ed25519: 64 bytes
			assert.Len(t, encoded, 64, "Ed25519 signature should be 64 bytes")
		}
	case "ethereum":
		// r(32) + s(32) + v(1) = 65 bytes
		assert.Len(t, encoded, 65, "Ethereum signature should be 65 bytes")
	case "bitcoin":
		if sigType == adapters.SignatureECDSA {
			// DER format
			assert.Equal(t, byte(0x30), encoded[0])
		} else {
			// BIP340: 64 bytes
			assert.Len(t, encoded, 64, "Schnorr signature should be 64 bytes")
		}
	case "solana":
		// Ed25519: 64 bytes
		assert.Len(t, encoded, 64, "Solana signature should be 64 bytes")
	}
}

// TestCrossChainCompatibility tests that keys can be used across compatible chains
func TestCrossChainCompatibility(t *testing.T) {
	// Test that the same ECDSA key works on multiple chains
	ecdsaChains := []string{"xrpl", "ethereum", "bitcoin"}
	
	// Create unified config with ECDSA
	config := &adapters.UnifiedConfig{
		ID:              "alice",
		Threshold:       2,
		SignatureScheme: adapters.SignatureECDSA,
		Group:          curve.Secp256k1{},
		SecretShare:     curve.Secp256k1{}.NewScalar(),
		PublicKey:       curve.Secp256k1{}.NewGenerator(),
	}
	
	factory := &adapters.AdapterFactory{}
	
	for _, chain := range ecdsaChains {
		adapter := factory.NewAdapter(chain, adapters.SignatureECDSA)
		err := adapter.ValidateConfig(config)
		assert.NoError(t, err, "ECDSA config should work on %s", chain)
	}
	
	// Test Ed25519 chains
	ed25519Chains := []string{"xrpl", "solana"}
	
	config.SignatureScheme = adapters.SignatureEdDSA
	config.Group = curve.Edwards25519{}
	config.SecretShare = curve.Edwards25519{}.NewScalar()
	config.PublicKey = curve.Edwards25519{}.NewGenerator()
	
	for _, chain := range ed25519Chains {
		adapter := factory.NewAdapter(chain, adapters.SignatureEdDSA)
		err := adapter.ValidateConfig(config)
		assert.NoError(t, err, "Ed25519 config should work on %s", chain)
	}
}

// TestEndToEndThresholdSignature tests complete threshold signature flow
func TestEndToEndThresholdSignature(t *testing.T) {
	// Simulate 3-of-5 threshold signing
	n := 5
	threshold := 3
	
	// Test each supported chain
	chains := []struct {
		name    string
		sigType adapters.SignatureType
	}{
		{"xrpl", adapters.SignatureECDSA},
		{"ethereum", adapters.SignatureECDSA},
		{"bitcoin", adapters.SignatureSchnorr},
		{"solana", adapters.SignatureEdDSA},
	}
	
	for _, chain := range chains {
		t.Run(chain.name, func(t *testing.T) {
			factory := &adapters.AdapterFactory{}
			adapter := factory.NewAdapter(chain.name, chain.sigType)
			
			// Create shares
			shares := createMockShares(t, chain.sigType, n, threshold)
			
			// Create message
			message := []byte(fmt.Sprintf("test message for %s", chain.name))
			digest, err := adapter.Digest(message)
			require.NoError(t, err)
			
			// Each party creates partial signature
			var partials []adapters.PartialSig
			for i := 0; i < threshold; i++ {
				partial, err := adapter.SignEC(digest, shares[i])
				require.NoError(t, err)
				partials = append(partials, partial)
			}
			
			// Aggregate signatures
			fullSig, err := adapter.AggregateEC(partials)
			require.NoError(t, err)
			
			// Encode for wire format
			encoded, err := adapter.Encode(fullSig)
			require.NoError(t, err)
			
			// Verify encoding is valid
			assert.NotEmpty(t, encoded)
			t.Logf("%s signature size: %d bytes", chain.name, len(encoded))
		})
	}
}

// TestAdapterErrorHandling tests error cases
func TestAdapterErrorHandling(t *testing.T) {
	t.Run("InvalidDigestInput", func(t *testing.T) {
		adapter := adapters.NewXRPLAdapter(adapters.SignatureECDSA, false)
		
		// Invalid input type
		_, err := adapter.Digest(123)
		assert.Error(t, err)
	})

	t.Run("InsufficientPartialSignatures", func(t *testing.T) {
		adapter := adapters.NewEthereumAdapter()
		
		// Empty partial signatures
		_, err := adapter.AggregateEC([]adapters.PartialSig{})
		assert.Error(t, err)
	})

	t.Run("MismatchedSignatureType", func(t *testing.T) {
		adapter := adapters.NewSolanaAdapter()
		
		// Try to use ECDSA signature with Ed25519 adapter
		ecdsaSig := &adapters.ECDSAFullSig{
			R: curve.Secp256k1{}.NewScalar(),
			S: curve.Secp256k1{}.NewScalar(),
		}
		
		_, err := adapter.Encode(ecdsaSig)
		assert.Error(t, err)
	})

	t.Run("InvalidConfiguration", func(t *testing.T) {
		adapter := adapters.NewBitcoinAdapter(adapters.SignatureSchnorr)
		
		// Wrong curve for Bitcoin
		config := &adapters.UnifiedConfig{
			SignatureScheme: adapters.SignatureSchnorr,
			Group:          curve.Edwards25519{}, // Wrong curve
		}
		
		err := adapter.ValidateConfig(config)
		assert.Error(t, err)
	})
}

// TestParallelSigning tests concurrent signing operations
func TestParallelSigning(t *testing.T) {
	adapter := adapters.NewXRPLAdapter(adapters.SignatureECDSA, false)
	shares := createMockShares(t, adapters.SignatureECDSA, 10, 6)
	
	message := []byte("parallel test message")
	digest, err := adapter.Digest(message)
	require.NoError(t, err)
	
	// Sign in parallel
	type result struct {
		partial adapters.PartialSig
		err     error
	}
	
	results := make(chan result, 6)
	
	for i := 0; i < 6; i++ {
		go func(share adapters.Share) {
			partial, err := adapter.SignEC(digest, share)
			results <- result{partial, err}
		}(shares[i])
	}
	
	// Collect results
	var partials []adapters.PartialSig
	for i := 0; i < 6; i++ {
		res := <-results
		require.NoError(t, res.err)
		partials = append(partials, res.partial)
	}
	
	// Aggregate
	fullSig, err := adapter.AggregateEC(partials)
	require.NoError(t, err)
	assert.NotNil(t, fullSig)
}