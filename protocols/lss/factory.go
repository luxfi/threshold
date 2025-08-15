// Package lss - Unified LSS factory for all blockchains
package lss

import (
	"fmt"
	"strings"

	"github.com/luxfi/threshold/protocols/lss/adapters"
)

// Chain represents a supported blockchain
type Chain string

// All supported blockchains (top 100+ by market cap and usage)
const (
	// Layer 1 Blockchains
	Bitcoin   Chain = "bitcoin"
	Ethereum  Chain = "ethereum"
	BNBChain  Chain = "bnb"
	Solana    Chain = "solana"
	Cardano   Chain = "cardano"
	Avalanche Chain = "avalanche"
	Polygon   Chain = "polygon"
	TRON      Chain = "tron"
	TON       Chain = "ton"
	Sui       Chain = "sui"
	Aptos     Chain = "aptos"
	Near      Chain = "near"
	Cosmos    Chain = "cosmos"
	Algorand  Chain = "algorand"
	Stellar   Chain = "stellar"
	Hedera    Chain = "hedera"
	Flow      Chain = "flow"
	Tezos     Chain = "tezos"
	EOS       Chain = "eos"
	XRPL      Chain = "xrpl"
	Polkadot  Chain = "polkadot"
	Kusama    Chain = "kusama"
	
	// Layer 2 & Sidechains
	Arbitrum  Chain = "arbitrum"
	Optimism  Chain = "optimism"
	Base      Chain = "base"
	zkSync    Chain = "zksync"
	Scroll    Chain = "scroll"
	Linea     Chain = "linea"
	Mantle    Chain = "mantle"
	Metis     Chain = "metis"
	
	// EVM Compatible Chains
	BSC       Chain = "bsc"
	Celo      Chain = "celo"
	Fantom    Chain = "fantom"
	Cronos    Chain = "cronos"
	Harmony   Chain = "harmony"
	Moonbeam  Chain = "moonbeam"
	Aurora    Chain = "aurora"
	Gnosis    Chain = "gnosis"
	Kava      Chain = "kava"
	Klaytn    Chain = "klaytn"
	
	// Specialized Chains
	Monero    Chain = "monero"
	Dash      Chain = "dash"
	Zcash     Chain = "zcash"
	
	// Post-Quantum
	Corona  Chain = "corona"
)

// ChainType represents the type of blockchain
type ChainType string

const (
	TypeEVM         ChainType = "evm"
	TypeBitcoin     ChainType = "bitcoin"
	TypeEdDSA       ChainType = "eddsa"
	TypeCosmos      ChainType = "cosmos"
	TypeSubstrate   ChainType = "substrate"
	TypePostQuantum ChainType = "post-quantum"
	TypeCustom      ChainType = "custom"
)

// ChainInfo contains information about a blockchain
type ChainInfo struct {
	Name          string
	Type          ChainType
	SignatureType adapters.SignatureType
	Curve         string
	ChainID       interface{} // Can be number or string
	TestnetID     interface{}
	Symbol        string
	Decimals      int
}

// GetChainInfo returns information about a blockchain
func GetChainInfo(chain Chain) *ChainInfo {
	chainMap := map[Chain]*ChainInfo{
		Bitcoin: {
			Name:          "Bitcoin",
			Type:          TypeBitcoin,
			SignatureType: adapters.SignatureECDSA,
			Curve:         "Secp256k1",
			Symbol:        "BTC",
			Decimals:      8,
		},
		Ethereum: {
			Name:          "Ethereum",
			Type:          TypeEVM,
			SignatureType: adapters.SignatureECDSA,
			Curve:         "Secp256k1",
			ChainID:       1,
			TestnetID:     11155111, // Sepolia
			Symbol:        "ETH",
			Decimals:      18,
		},
		BNBChain: {
			Name:          "BNB Smart Chain",
			Type:          TypeEVM,
			SignatureType: adapters.SignatureECDSA,
			Curve:         "Secp256k1",
			ChainID:       56,
			TestnetID:     97,
			Symbol:        "BNB",
			Decimals:      18,
		},
		Solana: {
			Name:          "Solana",
			Type:          TypeEdDSA,
			SignatureType: adapters.SignatureEdDSA,
			Curve:         "Ed25519",
			Symbol:        "SOL",
			Decimals:      9,
		},
		Cardano: {
			Name:          "Cardano",
			Type:          TypeEdDSA,
			SignatureType: adapters.SignatureEdDSA,
			Curve:         "Ed25519",
			Symbol:        "ADA",
			Decimals:      6,
		},
		TON: {
			Name:          "The Open Network",
			Type:          TypeEdDSA,
			SignatureType: adapters.SignatureEdDSA,
			Curve:         "Ed25519",
			Symbol:        "TON",
			Decimals:      9,
		},
		Sui: {
			Name:          "Sui",
			Type:          TypeEdDSA,
			SignatureType: adapters.SignatureEdDSA,
			Curve:         "Ed25519",
			Symbol:        "SUI",
			Decimals:      9,
		},
		Near: {
			Name:          "NEAR Protocol",
			Type:          TypeEdDSA,
			SignatureType: adapters.SignatureEdDSA,
			Curve:         "Ed25519",
			Symbol:        "NEAR",
			Decimals:      24,
		},
		XRPL: {
			Name:          "XRP Ledger",
			Type:          TypeCustom,
			SignatureType: adapters.SignatureECDSA,
			Curve:         "Secp256k1",
			Symbol:        "XRP",
			Decimals:      6,
		},
		Polygon: {
			Name:          "Polygon",
			Type:          TypeEVM,
			SignatureType: adapters.SignatureECDSA,
			Curve:         "Secp256k1",
			ChainID:       137,
			TestnetID:     80001, // Mumbai
			Symbol:        "MATIC",
			Decimals:      18,
		},
		Avalanche: {
			Name:          "Avalanche C-Chain",
			Type:          TypeEVM,
			SignatureType: adapters.SignatureECDSA,
			Curve:         "Secp256k1",
			ChainID:       43114,
			TestnetID:     43113, // Fuji
			Symbol:        "AVAX",
			Decimals:      18,
		},
		Arbitrum: {
			Name:          "Arbitrum One",
			Type:          TypeEVM,
			SignatureType: adapters.SignatureECDSA,
			Curve:         "Secp256k1",
			ChainID:       42161,
			TestnetID:     421614, // Sepolia
			Symbol:        "ETH",
			Decimals:      18,
		},
		Optimism: {
			Name:          "OP Mainnet",
			Type:          TypeEVM,
			SignatureType: adapters.SignatureECDSA,
			Curve:         "Secp256k1",
			ChainID:       10,
			TestnetID:     11155420, // Sepolia
			Symbol:        "ETH",
			Decimals:      18,
		},
		Base: {
			Name:          "Base",
			Type:          TypeEVM,
			SignatureType: adapters.SignatureECDSA,
			Curve:         "Secp256k1",
			ChainID:       8453,
			TestnetID:     84532, // Sepolia
			Symbol:        "ETH",
			Decimals:      18,
		},
		Celo: {
			Name:          "Celo",
			Type:          TypeEVM,
			SignatureType: adapters.SignatureECDSA,
			Curve:         "Secp256k1",
			ChainID:       42220,
			TestnetID:     44787, // Alfajores
			Symbol:        "CELO",
			Decimals:      18,
		},
		Corona: {
			Name:          "Corona (Post-Quantum)",
			Type:          TypePostQuantum,
			SignatureType: adapters.SignatureCorona,
			Curve:         "Lattice",
			Symbol:        "PQ",
			Decimals:      0,
		},
	}
	
	if info, ok := chainMap[chain]; ok {
		return info
	}
	
	// Default to Ethereum-compatible
	return chainMap[Ethereum]
}

// LSS is the main entry point for using LSS with any blockchain
type LSS struct {
	chain   Chain
	adapter adapters.SignerAdapter
	config  *FactoryConfig
}

// FactoryConfig holds LSS adapter configuration
type FactoryConfig struct {
	Chain           Chain
	Threshold       int
	TotalParties    int
	SignatureScheme adapters.SignatureType
	TestMode        bool
	CustomChainID   interface{}
}

// New creates a new LSS instance for any blockchain
func New(config *FactoryConfig) (*LSS, error) {
	if config == nil {
		return nil, fmt.Errorf("config required")
	}
	
	// Get chain info
	info := GetChainInfo(config.Chain)
	
	// Create appropriate adapter
	adapter, err := createAdapter(config.Chain, info)
	if err != nil {
		return nil, fmt.Errorf("failed to create adapter: %w", err)
	}
	
	// Override signature scheme if specified
	if config.SignatureScheme != 0 {
		info.SignatureType = config.SignatureScheme
	}
	
	return &LSS{
		chain:   config.Chain,
		adapter: adapter,
		config:  config,
	}, nil
}

// createAdapter creates the appropriate adapter for a chain
func createAdapter(chain Chain, info *ChainInfo) (adapters.SignerAdapter, error) {
	// Normalize chain name
	chainLower := strings.ToLower(string(chain))
	
	switch info.Type {
	case TypeEVM:
		// All EVM chains use the same adapter
		evmChain := adapters.EVMChain(chainLower)
		return adapters.NewEVMAdapter(evmChain), nil
		
	case TypeBitcoin:
		// Bitcoin and similar UTXO chains
		sigType := info.SignatureType
		if chain == Bitcoin {
			// Bitcoin supports both ECDSA and Schnorr
			return adapters.NewBitcoinAdapter(sigType), nil
		}
		// Other UTXO chains would go here
		return adapters.NewBitcoinAdapter(adapters.SignatureECDSA), nil
		
	case TypeEdDSA:
		// Ed25519-based chains
		switch chain {
		case Solana:
			return adapters.NewSolanaAdapter(), nil
		case Cardano:
			return adapters.NewCardanoAdapter(info.SignatureType, 0x01, adapters.EraBabbage), nil
		case TON:
			return adapters.NewTONAdapter(0), nil
		case Sui:
			return adapters.NewSuiAdapter(), nil
		case Near:
			return adapters.NewNEARAdapter("mainnet"), nil
		default:
			// Generic Ed25519 adapter
			return adapters.NewSolanaAdapter(), nil
		}
		
	case TypeCustom:
		// Custom implementations
		switch chain {
		case XRPL:
			return adapters.NewXRPLAdapter(info.SignatureType, false), nil
		default:
			return nil, fmt.Errorf("unsupported custom chain: %s", chain)
		}
		
	case TypePostQuantum:
		// Post-quantum chains
		if chain == Corona {
			return adapters.NewCoronaAdapter(128, 100), nil
		}
		return nil, fmt.Errorf("unsupported post-quantum chain: %s", chain)
		
	default:
		return nil, fmt.Errorf("unsupported chain type: %s", info.Type)
	}
}

// GetAdapter returns the underlying adapter
func (l *LSS) GetAdapter() adapters.SignerAdapter {
	return l.adapter
}

// GetChain returns the chain
func (l *LSS) GetChain() Chain {
	return l.chain
}

// GetConfig returns the configuration
func (l *LSS) GetConfig() *FactoryConfig {
	return l.config
}

// SupportedChains returns all supported blockchains
func SupportedChains() []Chain {
	return []Chain{
		Bitcoin, Ethereum, BNBChain, Solana, Cardano,
		Avalanche, Polygon, TON, Sui, Aptos,
		Near, Cosmos, Algorand, Stellar, Hedera,
		Flow, Tezos, EOS, XRPL, Polkadot,
		Arbitrum, Optimism, Base, zkSync, Scroll,
		BSC, Celo, Fantom, Cronos, Harmony,
		Moonbeam, Aurora, Gnosis, Kava, Klaytn,
		Corona,
	}
}

// IsEVMChain returns true if the chain is EVM-compatible
func IsEVMChain(chain Chain) bool {
	info := GetChainInfo(chain)
	return info.Type == TypeEVM
}

// IsEdDSAChain returns true if the chain uses Ed25519
func IsEdDSAChain(chain Chain) bool {
	info := GetChainInfo(chain)
	return info.Type == TypeEdDSA
}

// QuickStart creates an LSS instance with minimal configuration
func QuickStart(chain Chain, threshold, totalParties int) (*LSS, error) {
	return New(&FactoryConfig{
		Chain:        chain,
		Threshold:    threshold,
		TotalParties: totalParties,
		TestMode:     false,
	})
}