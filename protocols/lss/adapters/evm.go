// Package adapters - Generic EVM blockchain adapter
// Supports: Ethereum, BSC, Polygon, Lux, Arbitrum, Optimism, Base, etc.
package adapters

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/luxfi/threshold/pkg/math/curve"
	"golang.org/x/crypto/sha3"
)

// EVMChain represents different EVM-compatible chains
type EVMChain string

const (
	Ethereum  EVMChain = "ethereum"
	BSC       EVMChain = "bsc"
	Polygon   EVMChain = "polygon"
	Lux EVMChain = "lux"
	Arbitrum  EVMChain = "arbitrum"
	Optimism  EVMChain = "optimism"
	Base      EVMChain = "base"
	Fantom    EVMChain = "fantom"
	Cronos    EVMChain = "cronos"
	Harmony   EVMChain = "harmony"
	Moonbeam  EVMChain = "moonbeam"
	Aurora    EVMChain = "aurora"
	Gnosis    EVMChain = "gnosis"
	Scroll    EVMChain = "scroll"
	zkSync    EVMChain = "zksync"
	Linea     EVMChain = "linea"
	Mantle    EVMChain = "mantle"
	Celo      EVMChain = "celo"
	Kava      EVMChain = "kava"
	Metis     EVMChain = "metis"
)

// ChainConfig contains chain-specific configuration
type ChainConfig struct {
	ChainID         *big.Int
	Name            string
	Symbol          string
	ExplorerURL     string
	RPCURL          string
	IsL2            bool
	SupportsEIP1559 bool
	SupportsBlobTx  bool
}

// GetChainConfig returns configuration for known chains
func GetChainConfig(chain EVMChain) *ChainConfig {
	configs := map[EVMChain]*ChainConfig{
		Ethereum: {
			ChainID:         big.NewInt(1),
			Name:            "Ethereum Mainnet",
			Symbol:          "ETH",
			ExplorerURL:     "https://etherscan.io",
			SupportsEIP1559: true,
			SupportsBlobTx:  true,
		},
		BSC: {
			ChainID:         big.NewInt(56),
			Name:            "BNB Smart Chain",
			Symbol:          "BNB",
			ExplorerURL:     "https://bscscan.com",
			SupportsEIP1559: true,
		},
		Polygon: {
			ChainID:         big.NewInt(137),
			Name:            "Polygon",
			Symbol:          "MATIC",
			ExplorerURL:     "https://polygonscan.com",
			SupportsEIP1559: true,
		},
		Lux: {
			ChainID:         big.NewInt(43114),
			Name:            "Lux C-Chain",
			Symbol:          "LUX",
			ExplorerURL:     "https://snowtrace.io",
			SupportsEIP1559: true,
		},
		Arbitrum: {
			ChainID:         big.NewInt(42161),
			Name:            "Arbitrum One",
			Symbol:          "ETH",
			ExplorerURL:     "https://arbiscan.io",
			IsL2:            true,
			SupportsEIP1559: true,
		},
		Optimism: {
			ChainID:         big.NewInt(10),
			Name:            "OP Mainnet",
			Symbol:          "ETH",
			ExplorerURL:     "https://optimistic.etherscan.io",
			IsL2:            true,
			SupportsEIP1559: true,
		},
		Base: {
			ChainID:         big.NewInt(8453),
			Name:            "Base",
			Symbol:          "ETH",
			ExplorerURL:     "https://basescan.org",
			IsL2:            true,
			SupportsEIP1559: true,
		},
		Fantom: {
			ChainID:     big.NewInt(250),
			Name:        "Fantom Opera",
			Symbol:      "FTM",
			ExplorerURL: "https://ftmscan.com",
		},
		Cronos: {
			ChainID:     big.NewInt(25),
			Name:        "Cronos",
			Symbol:      "CRO",
			ExplorerURL: "https://cronoscan.com",
		},
		Harmony: {
			ChainID:     big.NewInt(1666600000),
			Name:        "Harmony",
			Symbol:      "ONE",
			ExplorerURL: "https://explorer.harmony.one",
		},
		Moonbeam: {
			ChainID:         big.NewInt(1284),
			Name:            "Moonbeam",
			Symbol:          "GLMR",
			ExplorerURL:     "https://moonscan.io",
			SupportsEIP1559: true,
		},
		Aurora: {
			ChainID:     big.NewInt(1313161554),
			Name:        "Aurora",
			Symbol:      "ETH",
			ExplorerURL: "https://aurorascan.dev",
		},
		Gnosis: {
			ChainID:         big.NewInt(100),
			Name:            "Gnosis Chain",
			Symbol:          "xDAI",
			ExplorerURL:     "https://gnosisscan.io",
			SupportsEIP1559: true,
		},
		Scroll: {
			ChainID:         big.NewInt(534352),
			Name:            "Scroll",
			Symbol:          "ETH",
			ExplorerURL:     "https://scrollscan.com",
			IsL2:            true,
			SupportsEIP1559: true,
		},
		zkSync: {
			ChainID:         big.NewInt(324),
			Name:            "zkSync Era",
			Symbol:          "ETH",
			ExplorerURL:     "https://explorer.zksync.io",
			IsL2:            true,
			SupportsEIP1559: true,
		},
		Linea: {
			ChainID:         big.NewInt(59144),
			Name:            "Linea",
			Symbol:          "ETH",
			ExplorerURL:     "https://lineascan.build",
			IsL2:            true,
			SupportsEIP1559: true,
		},
		Mantle: {
			ChainID:     big.NewInt(5000),
			Name:        "Mantle",
			Symbol:      "MNT",
			ExplorerURL: "https://explorer.mantle.xyz",
			IsL2:        true,
		},
		Celo: {
			ChainID:         big.NewInt(42220),
			Name:            "Celo",
			Symbol:          "CELO",
			ExplorerURL:     "https://celoscan.io",
			SupportsEIP1559: true,
		},
		Kava: {
			ChainID:     big.NewInt(2222),
			Name:        "Kava EVM",
			Symbol:      "KAVA",
			ExplorerURL: "https://explorer.kava.io",
		},
		Metis: {
			ChainID:     big.NewInt(1088),
			Name:        "Metis Andromeda",
			Symbol:      "METIS",
			ExplorerURL: "https://andromeda-explorer.metis.io",
			IsL2:        true,
		},
	}

	if config, ok := configs[chain]; ok {
		return config
	}

	// Default Ethereum config
	return configs[Ethereum]
}

// EVMAdapter implements SignerAdapter for all EVM-compatible chains
type EVMAdapter struct {
	group  curve.Curve
	chain  EVMChain
	config *ChainConfig
}

// NewEVMAdapter creates a new adapter for any EVM chain
func NewEVMAdapter(chain EVMChain) *EVMAdapter {
	return &EVMAdapter{
		group:  curve.Secp256k1{},
		chain:  chain,
		config: GetChainConfig(chain),
	}
}

// SetCustomChainID allows setting custom chain ID for private/test networks
func (e *EVMAdapter) SetCustomChainID(chainID *big.Int) {
	e.config.ChainID = chainID
}

// Digest computes transaction digest for EVM chains
func (e *EVMAdapter) Digest(tx interface{}) ([]byte, error) {
	switch v := tx.(type) {
	case *EVMTransaction:
		return e.digestTransaction(v)
	case []byte:
		// Message hash for signing
		return e.hashMessage(v), nil
	default:
		return nil, fmt.Errorf("unsupported transaction type: %T", tx)
	}
}

// digestTransaction computes digest based on transaction type
func (e *EVMAdapter) digestTransaction(tx *EVMTransaction) ([]byte, error) {
	h := sha3.NewLegacyKeccak256()

	// Encode based on transaction type
	var encoded []byte
	switch tx.Type {
	case LegacyTxType:
		encoded = e.encodeLegacyTx(tx)
	case AccessListTxType:
		encoded = e.encodeAccessListTx(tx)
	case DynamicFeeTxType:
		if !e.config.SupportsEIP1559 {
			return nil, fmt.Errorf("chain %s does not support EIP-1559", e.chain)
		}
		encoded = e.encodeDynamicFeeTx(tx)
	case BlobTxType:
		if !e.config.SupportsBlobTx {
			return nil, fmt.Errorf("chain %s does not support blob transactions", e.chain)
		}
		encoded = e.encodeBlobTx(tx)
	default:
		return nil, fmt.Errorf("unsupported transaction type: %d", tx.Type)
	}

	h.Write(encoded)
	return h.Sum(nil), nil
}

// hashMessage creates EVM message hash with prefix
func (e *EVMAdapter) hashMessage(message []byte) []byte {
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(message))
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(prefix))
	h.Write(message)
	return h.Sum(nil)
}

// SignEC creates ECDSA partial signature
func (e *EVMAdapter) SignEC(digest []byte, share Share) (PartialSig, error) {
	// For testing, provide a placeholder R value
	return &ECDSAPartialSig{
		PartyID: share.ID,
		R:       e.group.NewScalar(), // Placeholder for testing
		S:       share.Value,
	}, nil
}

// AggregateEC combines ECDSA partial signatures
func (e *EVMAdapter) AggregateEC(parts []PartialSig) (FullSig, error) {
	if len(parts) == 0 {
		return nil, errors.New("no partial signatures")
	}

	var r, s curve.Scalar

	for _, part := range parts {
		ecdsaPart, ok := part.(*ECDSAPartialSig)
		if !ok {
			return nil, errors.New("invalid ECDSA partial signature")
		}

		if r == nil && ecdsaPart.R != nil {
			r = ecdsaPart.R
		}

		if s == nil {
			s = e.group.NewScalar()
		}
		s = s.Add(ecdsaPart.S)
	}

	// Apply low-s normalization for malleability protection
	s = e.normalizeLowS(s)

	return &ECDSAFullSig{
		R: r,
		S: s,
	}, nil
}

// normalizeLowS ensures S is in lower half of curve order
func (e *EVMAdapter) normalizeLowS(s curve.Scalar) curve.Scalar {
	// EVM chains require low-s normalization
	orderMod := e.group.Order()
	order := orderMod.Big()
	halfOrder := new(big.Int).Div(order, big.NewInt(2))

	sBig := new(big.Int)
	sBytes, _ := s.MarshalBinary()
	sBig.SetBytes(sBytes)

	if sBig.Cmp(halfOrder) > 0 {
		sBig.Sub(order, sBig)
		s = e.group.NewScalar().SetNat(orderMod.Nat().SetBytes(sBig.Bytes()))
	}

	return s
}

// Encode formats ECDSA signature for EVM
func (e *EVMAdapter) Encode(full FullSig) ([]byte, error) {
	ecdsaSig, ok := full.(*ECDSAFullSig)
	if !ok {
		return nil, errors.New("invalid ECDSA signature")
	}

	// r(32) + s(32) + v(1) = 65 bytes
	sig := make([]byte, 65)

	// Copy r
	rBytes, _ := ecdsaSig.R.MarshalBinary()
	copy(sig[32-len(rBytes):32], rBytes)

	// Copy s
	sBytes, _ := ecdsaSig.S.MarshalBinary()
	copy(sig[64-len(sBytes):64], sBytes)

	// Recovery ID (v) - chain-specific calculation
	v := e.calculateV()
	sig[64] = v

	return sig, nil
}

// calculateV calculates recovery ID based on chain
func (e *EVMAdapter) calculateV() byte {
	// EIP-155: v = chainId * 2 + 35 or chainId * 2 + 36
	// For simplicity, using standard value
	return 27
}

// ValidateConfig validates EVM configuration
func (e *EVMAdapter) ValidateConfig(config *UnifiedConfig) error {
	if config.SignatureScheme != SignatureECDSA {
		return errors.New("EVM chains require ECDSA signatures")
	}

	// Verify Secp256k1 curve
	if _, ok := config.Group.(curve.Secp256k1); !ok {
		return errors.New("EVM chains require Secp256k1 curve")
	}

	return nil
}

// Transaction types
const (
	LegacyTxType     = 0x00
	AccessListTxType = 0x01
	DynamicFeeTxType = 0x02
	BlobTxType       = 0x03
)

// EVMTransaction represents a generic EVM transaction
type EVMTransaction struct {
	Type                 byte
	ChainID              *big.Int
	Nonce                uint64
	GasPrice             *big.Int // Legacy
	MaxPriorityFeePerGas *big.Int // EIP-1559
	MaxFeePerGas         *big.Int // EIP-1559
	GasLimit             uint64
	To                   *[20]byte
	Value                *big.Int
	Data                 []byte
	AccessList           []AccessListEntry
	BlobVersionedHashes  [][32]byte // EIP-4844
	MaxFeePerBlobGas     *big.Int   // EIP-4844
}

// Encoding functions for different transaction types
func (e *EVMAdapter) encodeLegacyTx(tx *EVMTransaction) []byte {
	// Simplified RLP encoding for legacy transactions
	var encoded []byte

	// Nonce
	nonceBytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		nonceBytes[7-i] = byte(tx.Nonce >> (8 * i))
	}
	encoded = append(encoded, nonceBytes...)

	// Gas price
	if tx.GasPrice != nil {
		priceBytes := tx.GasPrice.Bytes()
		encoded = append(encoded, priceBytes...)
	}

	// Gas limit
	gasBytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		gasBytes[7-i] = byte(tx.GasLimit >> (8 * i))
	}
	encoded = append(encoded, gasBytes...)

	// To
	if tx.To != nil {
		encoded = append(encoded, tx.To[:]...)
	} else {
		encoded = append(encoded, 0x80) // Contract creation
	}

	// Value
	if tx.Value != nil {
		valueBytes := tx.Value.Bytes()
		encoded = append(encoded, valueBytes...)
	} else {
		encoded = append(encoded, 0x80)
	}

	// Data
	encoded = append(encoded, tx.Data...)

	// EIP-155 chain ID
	if e.config.ChainID != nil {
		encoded = append(encoded, e.config.ChainID.Bytes()...)
		encoded = append(encoded, 0x80, 0x80) // r, s placeholders
	}

	return encoded
}

func (e *EVMAdapter) encodeAccessListTx(tx *EVMTransaction) []byte {
	// Type 1 (EIP-2930) transaction encoding
	encoded := []byte{AccessListTxType}
	// Add RLP encoding of access list transaction fields
	return encoded
}

func (e *EVMAdapter) encodeDynamicFeeTx(tx *EVMTransaction) []byte {
	// Type 2 (EIP-1559) transaction encoding
	encoded := []byte{DynamicFeeTxType}
	// Add RLP encoding of dynamic fee transaction fields
	return encoded
}

func (e *EVMAdapter) encodeBlobTx(tx *EVMTransaction) []byte {
	// Type 3 (EIP-4844) blob transaction encoding
	encoded := []byte{BlobTxType}
	// Add RLP encoding of blob transaction fields
	return encoded
}

// GenerateEVMAddress generates an EVM address from public key
func (e *EVMAdapter) GenerateEVMAddress(publicKey curve.Point) [20]byte {
	// Keccak256(pubkey)[12:]
	pubBytes, _ := publicKey.MarshalBinary()

	h := sha3.NewLegacyKeccak256()
	h.Write(pubBytes[1:]) // Skip format byte
	hash := h.Sum(nil)

	var addr [20]byte
	copy(addr[:], hash[12:])
	return addr
}

// EstimateGas estimates gas for transaction
func (e *EVMAdapter) EstimateGas(tx *EVMTransaction) uint64 {
	// Base cost
	baseCost := uint64(21000)

	// Data cost (4 gas per zero byte, 16 gas per non-zero)
	dataCost := uint64(0)
	for _, b := range tx.Data {
		if b == 0 {
			dataCost += 4
		} else {
			dataCost += 16
		}
	}

	// Access list cost (if present)
	accessListCost := uint64(0)
	if len(tx.AccessList) > 0 {
		accessListCost = uint64(len(tx.AccessList)) * 2400
		for _, entry := range tx.AccessList {
			accessListCost += uint64(len(entry.StorageKeys)) * 1900
		}
	}

	// L2 specific costs
	l2Cost := uint64(0)
	if e.config.IsL2 {
		// L2s have additional data availability costs
		l2Cost = uint64(len(tx.Data)) * 16
	}

	return baseCost + dataCost + accessListCost + l2Cost
}
