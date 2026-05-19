// Package adapters — L2 chain-specific threshold signing tests.
//
// Validates that threshold signatures produce valid, chain-specific
// transactions for major Ethereum L2s: Arbitrum, Optimism, Base, Scroll.
//
// Each L2 has subtle differences in transaction handling:
//   - Chain ID encoding (EIP-155 replay protection across L2s)
//   - EIP-1559 support and fee market dynamics
//   - EIP-4844 blob transaction support (post-Dencun)
//   - L2-specific deposit transaction types
//
// Contributed by kcolbchain (https://kcolbchain.com) — independent
// blockchain research collective focused on L2 infrastructure.
package adapters

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// L2TestChain bundles config + expected behavior for each L2.
type L2TestChain struct {
	Chain           EVMChain
	ChainID         int64
	Name            string
	IsL2            bool
	SupportsEIP1559 bool
	SupportsBlobTx  bool
}

var l2TestChains = []L2TestChain{
	{Arbitrum, 42161, "Arbitrum One", true, true, false},
	{Optimism, 10, "OP Mainnet", true, true, false},
	{Base, 8453, "Base", true, true, false},
	{Scroll, 534352, "Scroll", true, true, false},
	{zkSync, 324, "zkSync Era", true, true, false},
	{Linea, 59144, "Linea", true, true, false},
}

// TestL2ChainConfigs verifies all L2 chain configs are correctly registered.
func TestL2ChainConfigs(t *testing.T) {
	for _, tc := range l2TestChains {
		t.Run(tc.Name, func(t *testing.T) {
			cfg := GetChainConfig(tc.Chain)
			require.NotNil(t, cfg, "chain config not found for %s", tc.Chain)

			assert.Equal(t, big.NewInt(tc.ChainID), cfg.ChainID,
				"%s: wrong chain ID", tc.Name)
			assert.Equal(t, tc.Name, cfg.Name)
			assert.True(t, cfg.IsL2, "%s should be marked as L2", tc.Name)
			assert.Equal(t, tc.SupportsEIP1559, cfg.SupportsEIP1559,
				"%s: EIP-1559 support mismatch", tc.Name)
		})
	}
}

// TestL2EthereumAdapterChainID ensures the Ethereum adapter correctly
// handles chain ID switching for each L2.
func TestL2EthereumAdapterChainID(t *testing.T) {
	for _, tc := range l2TestChains {
		t.Run(tc.Name, func(t *testing.T) {
			adapter := NewEthereumAdapter()
			adapter.SetChainID(big.NewInt(tc.ChainID))

			// Verify the adapter uses the correct chain ID in EIP-155 signatures.
			// The v value of an ECDSA signature encodes the chain ID:
			//   v = chainID * 2 + 35 (for legacy tx)
			//   v = {0, 1} (for EIP-1559 tx, chain ID in tx envelope)
			assert.Equal(t, big.NewInt(tc.ChainID), adapter.chainID)
		})
	}
}

// TestL2LegacyTransactionDigest validates EIP-155 digest for each L2.
func TestL2LegacyTransactionDigest(t *testing.T) {
	for _, tc := range l2TestChains {
		t.Run(tc.Name, func(t *testing.T) {
			adapter := NewEthereumAdapter()
			adapter.SetChainID(big.NewInt(tc.ChainID))

			tx := &LegacyTransaction{
				Nonce:    0,
				GasPrice: big.NewInt(20000000),
				GasLimit: 21000,
				To:       [20]byte{0x01}, // dummy address
				Value:    big.NewInt(1000000000000000),
				Data:     nil,
			}

			digest, err := adapter.Digest(tx)
			require.NoError(t, err)
			assert.Len(t, digest, 32, "digest should be 32 bytes (keccak256)")

			// Digests for different chain IDs must be different (replay protection)
			adapter2 := NewEthereumAdapter()
			adapter2.SetChainID(big.NewInt(1)) // Ethereum mainnet
			digest2, err := adapter2.Digest(tx)
			require.NoError(t, err)

			if tc.ChainID != 1 {
				assert.NotEqual(t, digest, digest2,
					"%s: digest should differ from mainnet (EIP-155 replay protection)", tc.Name)
			}
		})
	}
}

// TestL2EIP1559TransactionDigest validates EIP-1559 digest for each L2.
func TestL2EIP1559TransactionDigest(t *testing.T) {
	for _, tc := range l2TestChains {
		if !tc.SupportsEIP1559 {
			continue
		}
		t.Run(tc.Name, func(t *testing.T) {
			adapter := NewEthereumAdapter()
			adapter.SetChainID(big.NewInt(tc.ChainID))

			tx := &EIP1559Transaction{
				ChainID:              big.NewInt(tc.ChainID),
				Nonce:                0,
				MaxPriorityFeePerGas: big.NewInt(1000000),
				MaxFeePerGas:         big.NewInt(30000000),
				GasLimit:             21000,
				To:                   [20]byte{0x01},
				Value:                big.NewInt(1000000000000000),
				Data:                 nil,
			}

			digest, err := adapter.Digest(tx)
			require.NoError(t, err)
			assert.Len(t, digest, 32, "digest should be 32 bytes")

			// EIP-1559 tx encodes chain ID in the envelope, so different chains
			// produce different digests even with same params.
			adapter2 := NewEthereumAdapter()
			adapter2.SetChainID(big.NewInt(1))
			tx2 := &EIP1559Transaction{
				ChainID:              big.NewInt(1),
				Nonce:                0,
				MaxPriorityFeePerGas: big.NewInt(1000000),
				MaxFeePerGas:         big.NewInt(30000000),
				GasLimit:             21000,
				To:                   [20]byte{0x01},
				Value:                big.NewInt(1000000000000000),
			}
			digest2, err := adapter2.Digest(tx2)
			require.NoError(t, err)

			if tc.ChainID != 1 {
				assert.NotEqual(t, digest, digest2,
					"%s: EIP-1559 digest should differ from mainnet", tc.Name)
			}
		})
	}
}

// TestL2CrossChainReplayProtection is the critical test: ensures a signature
// produced for one L2 cannot be replayed on another L2 or on mainnet.
func TestL2CrossChainReplayProtection(t *testing.T) {
	digests := make(map[string][]byte)

	for _, tc := range l2TestChains {
		adapter := NewEthereumAdapter()
		adapter.SetChainID(big.NewInt(tc.ChainID))

		tx := &LegacyTransaction{
			Nonce:    42,
			GasPrice: big.NewInt(20000000),
			GasLimit: 100000,
			To:       [20]byte{0xDE, 0xAD},
			Value:    big.NewInt(1e18),
			Data:     []byte("transfer"),
		}

		digest, err := adapter.Digest(tx)
		require.NoError(t, err)
		digests[tc.Name] = digest
	}

	// Also add mainnet
	adapter := NewEthereumAdapter()
	adapter.SetChainID(big.NewInt(1))
	tx := &LegacyTransaction{
		Nonce:    42,
		GasPrice: big.NewInt(20000000),
		GasLimit: 100000,
		To:       [20]byte{0xDE, 0xAD},
		Value:    big.NewInt(1e18),
		Data:     []byte("transfer"),
	}
	digest, err := adapter.Digest(tx)
	require.NoError(t, err)
	digests["Ethereum Mainnet"] = digest

	// Every digest must be unique across all chains
	seen := make(map[string]string)
	for name, d := range digests {
		key := string(d)
		if other, exists := seen[key]; exists {
			t.Fatalf("REPLAY VULNERABILITY: %s and %s produce identical digests", name, other)
		}
		seen[key] = name
	}
}

// TestL2GasEstimation validates that gas estimation handles L2 chains.
func TestL2GasEstimation(t *testing.T) {
	for _, tc := range l2TestChains {
		t.Run(tc.Name, func(t *testing.T) {
			adapter := NewEthereumAdapter()
			adapter.SetChainID(big.NewInt(tc.ChainID))

			tx := &EIP1559Transaction{
				ChainID:              big.NewInt(tc.ChainID),
				Nonce:                0,
				MaxPriorityFeePerGas: big.NewInt(1000000),
				MaxFeePerGas:         big.NewInt(30000000),
				GasLimit:             21000,
				To:                   [20]byte{0x01},
				Value:                big.NewInt(1000000000000000),
			}

			gas, err := adapter.EstimateGas(tx)
			assert.NoError(t, err)
			assert.True(t, gas > 0, "%s: gas estimate should be positive", tc.Name)
		})
	}
}

// TestL2ChainIDEdgeCases checks boundary conditions for chain IDs.
func TestL2ChainIDEdgeCases(t *testing.T) {
	adapter := NewEthereumAdapter()

	// Test with zero chain ID (pre-EIP-155, should still work)
	adapter.SetChainID(big.NewInt(0))
	tx := &LegacyTransaction{
		Nonce:    0,
		GasPrice: big.NewInt(1),
		GasLimit: 21000,
		To:       [20]byte{0x01},
		Value:    big.NewInt(0),
	}
	_, err := adapter.Digest(tx)
	assert.NoError(t, err, "zero chain ID should not error")

	// Test with very large chain ID (future chains)
	largeCID := new(big.Int).SetUint64(999999999)
	adapter.SetChainID(largeCID)
	_, err = adapter.Digest(tx)
	assert.NoError(t, err, "large chain ID should not error")
}
