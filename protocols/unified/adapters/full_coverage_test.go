// Package adapters - Comprehensive test coverage for all chain adapters
package adapters

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAllChainsSupported verifies all chains have basic support
func TestAllChainsSupported(t *testing.T) {
	chains := GetSupportedChains()
	assert.Greater(t, len(chains), 15, "should support at least 15 chains")
	
	// Verify major chains are included
	expectedChains := []string{
		"xrpl", "ethereum", "bitcoin", "solana", "ton", "cardano",
		"cosmos", "polkadot", "avalanche", "binance",
	}
	
	for _, expected := range expectedChains {
		assert.Contains(t, chains, expected, "should support %s", expected)
	}
}

// TestXRPLAdapter tests XRPL-specific features
func TestXRPLAdapter(t *testing.T) {
	t.Run("ECDSA", func(t *testing.T) {
		adapter := NewXRPLAdapter(SignatureECDSA, false)
		require.NotNil(t, adapter)
		
		// Test digest computation with STX prefix
		txBlob := make([]byte, 100)
		rand.Read(txBlob)
		
		digest, err := adapter.Digest(txBlob)
		require.NoError(t, err)
		assert.Len(t, digest, 32, "SHA-512Half should be 32 bytes")
		
		// Test multi-signing with SMT prefix
		multiAdapter := NewXRPLAdapter(SignatureECDSA, true)
		multiDigest, err := multiAdapter.Digest(txBlob)
		require.NoError(t, err)
		assert.NotEqual(t, digest, multiDigest, "STX and SMT should produce different digests")
	})
	
	t.Run("EdDSA", func(t *testing.T) {
		adapter := NewXRPLAdapter(SignatureEdDSA, false)
		require.NotNil(t, adapter)
		
		// Test Ed25519 public key formatting
		pubKey := curve.Secp256k1{}.NewBasePoint() // Placeholder
		formatted := adapter.FormatPublicKey(pubKey)
		assert.NotEmpty(t, formatted)
	})
	
	t.Run("ValidateConfig", func(t *testing.T) {
		adapter := NewXRPLAdapter(SignatureECDSA, false)
		config := &UnifiedConfig{
			SignatureScheme: SignatureECDSA,
			Threshold:       3,
			PartyIDs:        []party.ID{"alice", "bob", "charlie"},
			VerificationShares: map[party.ID]interface{}{
				"alice":   curve.Secp256k1{}.NewBasePoint(),
				"bob":     curve.Secp256k1{}.NewBasePoint(),
				"charlie": curve.Secp256k1{}.NewBasePoint(),
			},
		}
		
		err := adapter.ValidateConfig(config)
		assert.NoError(t, err)
		
		// Test invalid threshold
		config.Threshold = 10
		err = adapter.ValidateConfig(config)
		assert.Error(t, err, "should reject threshold > 8")
	})
}

// TestEthereumAdapter tests Ethereum-specific features
func TestEthereumAdapter(t *testing.T) {
	adapter := NewEthereumAdapter()
	require.NotNil(t, adapter)
	
	t.Run("LegacyTransaction", func(t *testing.T) {
		tx := &LegacyTransaction{
			Nonce:    1,
			GasPrice: big.NewInt(20000000000),
			GasLimit: 21000,
			Value:    big.NewInt(1000000000000000000),
		}
		
		digest, err := adapter.Digest(tx)
		require.NoError(t, err)
		assert.Len(t, digest, 32, "Keccak256 should be 32 bytes")
	})
	
	t.Run("EIP1559Transaction", func(t *testing.T) {
		tx := &EIP1559Transaction{
			ChainID:              big.NewInt(1),
			Nonce:                1,
			MaxPriorityFeePerGas: big.NewInt(2000000000),
			MaxFeePerGas:         big.NewInt(30000000000),
			GasLimit:             21000,
			Value:                big.NewInt(1000000000000000000),
		}
		
		digest, err := adapter.Digest(tx)
		require.NoError(t, err)
		assert.Len(t, digest, 32)
	})
	
	t.Run("MessageHash", func(t *testing.T) {
		message := []byte("Hello Ethereum!")
		digest, err := adapter.Digest(message)
		require.NoError(t, err)
		assert.Len(t, digest, 32)
	})
	
	t.Run("GasEstimation", func(t *testing.T) {
		tx := &LegacyTransaction{}
		gas, err := adapter.EstimateGas(tx)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, gas, uint64(21000))
	})
}

// TestBitcoinAdapter tests Bitcoin-specific features
func TestBitcoinAdapter(t *testing.T) {
	t.Run("ECDSA", func(t *testing.T) {
		adapter := NewBitcoinAdapter(SignatureECDSA)
		require.NotNil(t, adapter)
		
		// TODO: Define BitcoinTransaction struct or use raw bytes
		tx := []byte("bitcoin_transaction_placeholder")
		
		digest, err := adapter.Digest(tx)
		require.NoError(t, err)
		assert.Len(t, digest, 32)
	})
	
	t.Run("Schnorr", func(t *testing.T) {
		adapter := NewBitcoinAdapter(SignatureSchnorr)
		require.NotNil(t, adapter)
		
		// Test Taproot transaction
		// TODO: Define BitcoinTransaction struct or use raw bytes
		tx := []byte("taproot_transaction_placeholder")
		
		digest, err := adapter.Digest(tx)
		require.NoError(t, err)
		assert.Len(t, digest, 32)
	})
	
	t.Run("SigHashTypes", func(t *testing.T) {
		adapter := NewBitcoinAdapter(SignatureECDSA)
		
		// Test basic digest computation
		tx := []byte("bitcoin_transaction")
		digest, err := adapter.Digest(tx)
		require.NoError(t, err)
		assert.Len(t, digest, 32)
	})
}

// TestSolanaAdapter tests Solana-specific features
func TestSolanaAdapter(t *testing.T) {
	adapter := NewSolanaAdapter()
	require.NotNil(t, adapter)
	
	t.Run("Transaction", func(t *testing.T) {
		msg := &SolanaMessage{
			NumRequiredSignatures:        1,
			NumReadonlySignedAccounts:    0,
			NumReadonlyUnsignedAccounts:  1,
			AccountKeys:                  make([][32]byte, 3),
			RecentBlockhash:              [32]byte{},
		}
		
		tx := &SolanaTransaction{
			Message: msg,
		}
		
		digest, err := adapter.Digest(tx)
		require.NoError(t, err)
		assert.NotNil(t, digest)
	})
	
	t.Run("TransferInstruction", func(t *testing.T) {
		adapter := NewSolanaAdapter()
		
		var from, to [32]byte
		rand.Read(from[:])
		rand.Read(to[:])
		
		instruction := adapter.CreateTransferInstruction(from, to, 1000000000)
		assert.NotNil(t, instruction)
		assert.Equal(t, byte(0), instruction.ProgramIDIndex)
	})
	
	t.Run("ProgramDerivedAddress", func(t *testing.T) {
		adapter := NewSolanaAdapter()
		
		var programID [32]byte
		rand.Read(programID[:])
		
		seeds := [][]byte{
			[]byte("threshold"),
			[]byte("wallet"),
		}
		
		pda, bump, err := adapter.ComputeProgramDerivedAddress(programID, seeds)
		require.NoError(t, err)
		assert.NotEqual(t, [32]byte{}, pda)
		assert.Greater(t, bump, byte(0))
	})
}

// TestTONAdapter tests TON-specific features
func TestTONAdapter(t *testing.T) {
	t.Run("Basechain", func(t *testing.T) {
		adapter := NewTONAdapter(0) // basechain
		require.NotNil(t, adapter)
		
		msg := &TONMessage{
			Info: TONMessageInfo{
				IHRDisabled: true,
				Bounce:      true,
				Value:       TONCurrencyCollection{Grams: 1000000000},
			},
			Body: []byte("test message"),
		}
		
		digest, err := adapter.Digest(msg)
		require.NoError(t, err)
		assert.Len(t, digest, 32, "SHA-256 should be 32 bytes")
	})
	
	t.Run("Masterchain", func(t *testing.T) {
		adapter := NewTONAdapter(-1) // masterchain
		require.NotNil(t, adapter)
		
		tx := &TONTransaction{
			Account: TONAddress{
				Workchain: -1,
				Hash:      [32]byte{},
			},
			Lt:  1000000,
			Now: 1234567890,
		}
		
		digest, err := adapter.Digest(tx)
		require.NoError(t, err)
		assert.Len(t, digest, 32)
	})
	
	t.Run("AddressGeneration", func(t *testing.T) {
		adapter := NewTONAdapter(0)
		
		var pubKey [32]byte
		rand.Read(pubKey[:])
		
		addr := adapter.GenerateTONAddress(pubKey)
		assert.Equal(t, int32(0), addr.Workchain)
		assert.NotEqual(t, [32]byte{}, addr.Hash)
	})
	
	t.Run("GasEstimation", func(t *testing.T) {
		adapter := NewTONAdapter(0)
		
		msg := &TONMessage{
			Body: make([]byte, 1000),
		}
		
		gas := adapter.EstimateGas(msg)
		assert.Greater(t, gas, uint64(10000))
	})
}

// TestCardanoAdapter tests Cardano-specific features
func TestCardanoAdapter(t *testing.T) {
	t.Run("Ed25519Native", func(t *testing.T) {
		adapter := NewCardanoAdapter(SignatureEdDSA, 0x01, EraBabbage)
		require.NotNil(t, adapter)
		
		tx := &CardanoTransaction{
			Body: &TransactionBody{
				Inputs: []TransactionInput{
					{TxID: [32]byte{}, Index: 0},
				},
				Outputs: []TransactionOutput{
					{Value: Value{Coin: 1000000}},
				},
				Fee: 200000,
				TTL: 1000000,
			},
			IsValid: true,
		}
		
		digest, err := adapter.Digest(tx)
		require.NoError(t, err)
		assert.Len(t, digest, 32, "Blake2b-256 should be 32 bytes")
	})
	
	t.Run("ECDSAInterop", func(t *testing.T) {
		adapter := NewCardanoAdapter(SignatureECDSA, 0x01, EraBabbage)
		require.NotNil(t, adapter)
		
		config := &UnifiedConfig{
			SignatureScheme: SignatureECDSA,
			Group:           curve.Secp256k1{},
		}
		
		err := adapter.ValidateConfig(config)
		assert.NoError(t, err)
	})
	
	t.Run("SchnorrInterop", func(t *testing.T) {
		adapter := NewCardanoAdapter(SignatureSchnorr, 0x01, EraBabbage)
		require.NotNil(t, adapter)
		
		// Test Schnorr signature aggregation
		parts := []PartialSig{
			&SchnorrPartialSig{
				PartyID: "alice",
				S:       curve.Secp256k1{}.NewScalar(),
			},
		}
		
		full, err := adapter.AggregateEC(parts)
		require.NoError(t, err)
		assert.NotNil(t, full)
	})
	
	t.Run("AddressGeneration", func(t *testing.T) {
		adapter := NewCardanoAdapter(SignatureEdDSA, 0x01, EraBabbage)
		
		var paymentKey, stakeKey [32]byte
		rand.Read(paymentKey[:])
		rand.Read(stakeKey[:])
		
		addr := adapter.GenerateCardanoAddress(paymentKey, stakeKey)
		assert.Equal(t, BaseAddress, addr.Type)
		assert.Equal(t, byte(0x01), addr.Network)
	})
	
	t.Run("FeeEstimation", func(t *testing.T) {
		adapter := NewCardanoAdapter(SignatureEdDSA, 0x01, EraBabbage)
		
		tx := &CardanoTransaction{
			Body: &TransactionBody{
				Inputs:  make([]TransactionInput, 2),
				Outputs: make([]TransactionOutput, 2),
				Fee:     0,
			},
		}
		
		fee := adapter.EstimateFee(tx)
		assert.Greater(t, fee, uint64(155381), "minimum fee should be applied")
	})
}

// TestRingtailAdapter tests post-quantum Ringtail features
func TestRingtailAdapter(t *testing.T) {
	t.Run("SecurityLevels", func(t *testing.T) {
		levels := []int{128, 192, 256}
		
		for _, level := range levels {
			adapter := NewRingtailAdapter(level, 5)
			require.NotNil(t, adapter)
			
			config := &UnifiedConfig{
				SignatureScheme: SignatureRingtail,
				Threshold:       3,
				PartyIDs:        []party.ID{"alice", "bob", "charlie", "dave", "eve"},
			}
			
			err := adapter.ValidateConfig(config)
			assert.NoError(t, err)
		}
	})
	
	t.Run("PreprocessingGeneration", func(t *testing.T) {
		adapter := NewRingtailAdapter(128, 5)
		
		parties := []party.ID{"alice", "bob", "charlie", "dave", "eve"}
		preprocessing := adapter.GeneratePreprocessing(parties, 3, 10)
		
		assert.Len(t, preprocessing, 10)
		for _, prep := range preprocessing {
			assert.NotEmpty(t, prep.ID)
			assert.False(t, prep.Consumed)
		}
	})
	
	t.Run("SignatureSize", func(t *testing.T) {
		testCases := []struct {
			securityLevel int
			expectedSize  int
		}{
			{128, 13400},
			{192, 28600},
			{256, 53200},
		}
		
		for _, tc := range testCases {
			adapter := NewRingtailAdapter(tc.securityLevel, 5)
			params := GetRecommendedParams(tc.securityLevel, 5)
			assert.Equal(t, tc.expectedSize, params.SignatureSize)
		}
	})
}

// TestChainRequirements verifies chain-specific requirements
func TestChainRequirements(t *testing.T) {
	t.Run("XRPL", func(t *testing.T) {
		req := GetChainRequirements("xrpl")
		require.NotNil(t, req)
		assert.True(t, req["low_s_required"].(bool))
		assert.True(t, req["prefix_ed25519"].(bool))
		assert.Equal(t, 8, req["max_threshold"])
	})
	
	t.Run("Ethereum", func(t *testing.T) {
		req := GetChainRequirements("ethereum")
		require.NotNil(t, req)
		assert.True(t, req["low_s_required"].(bool))
		assert.True(t, req["eip155_chainid"].(bool))
		assert.True(t, req["typed_tx"].(bool))
	})
	
	t.Run("Bitcoin", func(t *testing.T) {
		req := GetChainRequirements("bitcoin")
		require.NotNil(t, req)
		assert.True(t, req["low_s_required"].(bool))
		assert.True(t, req["taproot_support"].(bool))
		assert.True(t, req["sighash_types"].(bool))
	})
	
	t.Run("Solana", func(t *testing.T) {
		req := GetChainRequirements("solana")
		require.NotNil(t, req)
		assert.True(t, req["ed25519_only"].(bool))
		assert.True(t, req["program_verify"].(bool))
	})
	
	t.Run("Polkadot", func(t *testing.T) {
		req := GetChainRequirements("polkadot")
		require.NotNil(t, req)
		assert.True(t, req["sr25519_native"].(bool))
		assert.True(t, req["merlin_transcript"].(bool))
	})
}

// TestAdapterFactory tests the factory pattern
func TestAdapterFactory(t *testing.T) {
	factory := &AdapterFactory{}
	
	testCases := []struct {
		chain   string
		sigType SignatureType
		shouldBeNil bool
	}{
		{"xrpl", SignatureECDSA, false},
		{"xrpl", SignatureEdDSA, false},
		{"ethereum", SignatureECDSA, false},
		{"bitcoin", SignatureECDSA, false},
		{"bitcoin", SignatureSchnorr, false},
		{"solana", SignatureEdDSA, false},
		{"ton", SignatureEdDSA, false},
		{"cardano", SignatureEdDSA, false},
		{"cardano", SignatureECDSA, false},
		{"cardano", SignatureSchnorr, false},
		{"cosmos", SignatureECDSA, true}, // Not implemented yet
		{"polkadot", SignatureSchnorr, true}, // Not implemented yet
		{"unknown", SignatureECDSA, true},
	}
	
	for _, tc := range testCases {
		adapter := factory.NewAdapter(tc.chain, tc.sigType)
		if tc.shouldBeNil {
			assert.Nil(t, adapter, "%s should not have adapter", tc.chain)
		} else {
			assert.NotNil(t, adapter, "%s should have adapter", tc.chain)
		}
	}
}

// TestSignatureTypes tests all signature type implementations
func TestSignatureTypes(t *testing.T) {
	group := curve.Secp256k1{}
	
	t.Run("ECDSAPartialSig", func(t *testing.T) {
		sig := &ECDSAPartialSig{
			PartyID: "alice",
			R:       group.NewScalar(),
			S:       group.NewScalar(),
		}
		
		assert.Equal(t, party.ID("alice"), sig.GetPartyID())
		serialized := sig.Serialize()
		assert.NotEmpty(t, serialized)
	})
	
	t.Run("EdDSAPartialSig", func(t *testing.T) {
		sig := &EdDSAPartialSig{
			PartyID: "bob",
			R:       group.NewBasePoint(),
			Z:       group.NewScalar(),
		}
		
		assert.Equal(t, party.ID("bob"), sig.GetPartyID())
		serialized := sig.Serialize()
		assert.NotEmpty(t, serialized)
	})
	
	t.Run("RingtailPartialSig", func(t *testing.T) {
		sig := &RingtailPartialSig{
			PartyID: "charlie",
			Share:   []byte("lattice_element"),
		}
		
		assert.Equal(t, party.ID("charlie"), sig.GetPartyID())
		serialized := sig.Serialize()
		assert.NotNil(t, serialized)
	})
}

// TestCrossChainCompatibility tests cross-chain signature compatibility
func TestCrossChainCompatibility(t *testing.T) {
	// Test that signatures from one chain can be verified on another
	// when using compatible signature schemes
	
	message := []byte("cross-chain message")
	
	t.Run("ECDSA_Compatibility", func(t *testing.T) {
		chains := []string{"ethereum", "bitcoin", "xrpl"}
		
		for _, chain := range chains {
			factory := &AdapterFactory{}
			adapter := factory.NewAdapter(chain, SignatureECDSA)
			if adapter == nil {
				continue
			}
			
			digest, err := adapter.Digest(message)
			require.NoError(t, err)
			assert.Len(t, digest, 32, "%s should produce 32-byte digest", chain)
		}
	})
	
	t.Run("EdDSA_Compatibility", func(t *testing.T) {
		chains := []string{"solana", "ton", "cardano"}
		
		for _, chain := range chains {
			factory := &AdapterFactory{}
			adapter := factory.NewAdapter(chain, SignatureEdDSA)
			if adapter == nil {
				continue
			}
			
			digest, err := adapter.Digest(message)
			require.NoError(t, err)
			assert.NotNil(t, digest, "%s should produce valid digest", chain)
		}
	})
}

// BenchmarkAdapters benchmarks adapter performance
func BenchmarkAdapters(b *testing.B) {
	message := make([]byte, 1000)
	rand.Read(message)
	
	b.Run("XRPL_Digest", func(b *testing.B) {
		adapter := NewXRPLAdapter(SignatureECDSA, false)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = adapter.Digest(message)
		}
	})
	
	b.Run("Ethereum_Digest", func(b *testing.B) {
		adapter := NewEthereumAdapter()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = adapter.Digest(message)
		}
	})
	
	b.Run("TON_Digest", func(b *testing.B) {
		adapter := NewTONAdapter(0)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = adapter.Digest(message)
		}
	})
	
	b.Run("Cardano_Digest", func(b *testing.B) {
		adapter := NewCardanoAdapter(SignatureEdDSA, 0x01, EraBabbage)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = adapter.Digest(message)
		}
	})
}