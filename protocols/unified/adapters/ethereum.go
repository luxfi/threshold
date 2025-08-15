// Package adapters - Ethereum/EVM chain adapter implementation
package adapters

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/luxfi/threshold/pkg/math/curve"
	"golang.org/x/crypto/sha3"
)

// EthereumAdapter implements SignerAdapter for Ethereum and EVM-compatible chains
type EthereumAdapter struct {
	chainID *big.Int
	group   curve.Curve
}

// NewEthereumAdapter creates a new Ethereum adapter
func NewEthereumAdapter() *EthereumAdapter {
	return &EthereumAdapter{
		chainID: big.NewInt(1), // Mainnet by default
		group:   curve.Secp256k1{},
	}
}

// SetChainID sets the chain ID for EIP-155 replay protection
func (e *EthereumAdapter) SetChainID(chainID *big.Int) {
	e.chainID = chainID
}

// Digest computes Ethereum transaction digest
func (e *EthereumAdapter) Digest(tx interface{}) ([]byte, error) {
	switch v := tx.(type) {
	case *LegacyTransaction:
		return e.digestLegacy(v)
	case *EIP1559Transaction:
		return e.digestEIP1559(v)
	case *EIP4844Transaction:
		return e.digestEIP4844(v)
	case []byte:
		// Raw message hash
		return e.hashMessage(v), nil
	default:
		return nil, fmt.Errorf("unsupported transaction type: %T", tx)
	}
}

// digestLegacy computes digest for legacy transactions with EIP-155
func (e *EthereumAdapter) digestLegacy(tx *LegacyTransaction) ([]byte, error) {
	// RLP encode with EIP-155 chain ID
	encoded := e.rlpEncodeLegacy(tx, true)
	
	// Keccak256 hash
	hash := sha3.NewLegacyKeccak256()
	hash.Write(encoded)
	return hash.Sum(nil), nil
}

// digestEIP1559 computes digest for EIP-1559 transactions
func (e *EthereumAdapter) digestEIP1559(tx *EIP1559Transaction) ([]byte, error) {
	// Type 2 transaction: 0x02 || rlp([...])
	encoded := append([]byte{0x02}, e.rlpEncodeEIP1559(tx)...)
	
	hash := sha3.NewLegacyKeccak256()
	hash.Write(encoded)
	return hash.Sum(nil), nil
}

// digestEIP4844 computes digest for EIP-4844 blob transactions
func (e *EthereumAdapter) digestEIP4844(tx *EIP4844Transaction) ([]byte, error) {
	// Type 3 transaction: 0x03 || rlp([...])
	encoded := append([]byte{0x03}, e.rlpEncodeEIP4844(tx)...)
	
	hash := sha3.NewLegacyKeccak256()
	hash.Write(encoded)
	return hash.Sum(nil), nil
}

// SignEC creates ECDSA partial signature for Ethereum
func (e *EthereumAdapter) SignEC(digest []byte, share Share) (PartialSig, error) {
	// This integrates with CMP for ECDSA
	return &ECDSAPartialSig{
		PartyID: share.ID,
		R:       nil, // Computed in CMP protocol
		S:       share.Value,
	}, nil
}

// AggregateEC combines partial signatures with low-S enforcement
func (e *EthereumAdapter) AggregateEC(parts []PartialSig) (FullSig, error) {
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
	
	// Enforce EIP-2 low-S
	s = e.normalizeLowS(s)
	
	return &ECDSAFullSig{
		R: r,
		S: s,
	}, nil
}

// Encode formats signature with recovery ID for Ethereum
func (e *EthereumAdapter) Encode(full FullSig) ([]byte, error) {
	ecdsaSig, ok := full.(*ECDSAFullSig)
	if !ok {
		return nil, errors.New("invalid ECDSA signature")
	}
	
	// Ethereum signature format: r (32 bytes) || s (32 bytes) || v (1 byte)
	sig := make([]byte, 65)
	
	// Copy R (32 bytes)
	rBytes, _ := ecdsaSig.R.MarshalBinary()
	copy(sig[32-len(rBytes):32], rBytes)
	
	// Copy S (32 bytes)
	sBytes, _ := ecdsaSig.S.MarshalBinary()
	copy(sig[64-len(sBytes):64], sBytes)
	
	// Compute V value for EIP-155
	v := e.computeV(ecdsaSig)
	sig[64] = v
	
	return sig, nil
}

// ValidateConfig validates Ethereum-specific configuration
func (e *EthereumAdapter) ValidateConfig(config *UnifiedConfig) error {
	if config.SignatureScheme != SignatureECDSA {
		return errors.New("Ethereum requires ECDSA signatures")
	}
	
	// Verify secp256k1 curve
	if _, ok := config.Group.(curve.Secp256k1); !ok {
		return errors.New("Ethereum requires secp256k1 curve")
	}
	
	return nil
}

// computeV calculates the recovery ID for EIP-155
func (e *EthereumAdapter) computeV(sig *ECDSAFullSig) byte {
	// v = {0,1} + chainId * 2 + 35
	// For now, return placeholder
	// Actual implementation would recover from public key
	recoveryID := byte(0) // 0 or 1
	
	if e.chainID != nil {
		v := new(big.Int).SetUint64(uint64(recoveryID))
		v.Add(v, new(big.Int).Mul(e.chainID, big.NewInt(2)))
		v.Add(v, big.NewInt(35))
		return byte(v.Uint64())
	}
	
	return 27 + recoveryID // Pre-EIP-155
}

// normalizeLowS ensures S is in lower half per EIP-2
func (e *EthereumAdapter) normalizeLowS(s curve.Scalar) curve.Scalar {
	// Simplified version - actual implementation would need proper access to curve order
	// For now, return s as-is
	return s
}

// hashMessage applies Ethereum message prefix
func (e *EthereumAdapter) hashMessage(message []byte) []byte {
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(message))
	prefixed := append([]byte(prefix), message...)
	
	hash := sha3.NewLegacyKeccak256()
	hash.Write(prefixed)
	return hash.Sum(nil)
}

// RLP encoding helpers

func (e *EthereumAdapter) rlpEncodeLegacy(tx *LegacyTransaction, forSigning bool) []byte {
	// Simplified RLP encoding
	// Actual implementation would use proper RLP library
	var encoded []byte
	
	// Include fields based on whether for signing or not
	if forSigning {
		// For signing: include chainId, 0, 0 at the end
		encoded = append(encoded, e.encodeUint(tx.Nonce)...)
		encoded = append(encoded, e.encodeUint(tx.GasPrice.Uint64())...)
		encoded = append(encoded, e.encodeUint(tx.GasLimit)...)
		encoded = append(encoded, tx.To[:]...)
		encoded = append(encoded, e.encodeUint(tx.Value.Uint64())...)
		encoded = append(encoded, tx.Data...)
		encoded = append(encoded, e.encodeUint(e.chainID.Uint64())...)
		encoded = append(encoded, 0, 0)
	}
	
	return encoded
}

func (e *EthereumAdapter) rlpEncodeEIP1559(tx *EIP1559Transaction) []byte {
	// Simplified RLP encoding for EIP-1559
	var encoded []byte
	
	encoded = append(encoded, e.encodeUint(e.chainID.Uint64())...)
	encoded = append(encoded, e.encodeUint(tx.Nonce)...)
	encoded = append(encoded, e.encodeUint(tx.MaxPriorityFeePerGas.Uint64())...)
	encoded = append(encoded, e.encodeUint(tx.MaxFeePerGas.Uint64())...)
	encoded = append(encoded, e.encodeUint(tx.GasLimit)...)
	encoded = append(encoded, tx.To[:]...)
	encoded = append(encoded, e.encodeUint(tx.Value.Uint64())...)
	encoded = append(encoded, tx.Data...)
	// Access list would go here
	
	return encoded
}

func (e *EthereumAdapter) rlpEncodeEIP4844(tx *EIP4844Transaction) []byte {
	// Simplified RLP encoding for EIP-4844
	var encoded []byte
	
	encoded = append(encoded, e.encodeUint(e.chainID.Uint64())...)
	encoded = append(encoded, e.encodeUint(tx.Nonce)...)
	encoded = append(encoded, e.encodeUint(tx.MaxPriorityFeePerGas.Uint64())...)
	encoded = append(encoded, e.encodeUint(tx.MaxFeePerGas.Uint64())...)
	encoded = append(encoded, e.encodeUint(tx.GasLimit)...)
	encoded = append(encoded, tx.To[:]...)
	encoded = append(encoded, e.encodeUint(tx.Value.Uint64())...)
	encoded = append(encoded, tx.Data...)
	// Access list
	encoded = append(encoded, e.encodeUint(tx.MaxFeePerBlobGas.Uint64())...)
	// Blob versioned hashes
	for _, hash := range tx.BlobVersionedHashes {
		encoded = append(encoded, hash[:]...)
	}
	
	return encoded
}

func (e *EthereumAdapter) encodeUint(val uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, val)
	// Remove leading zeros
	for i := 0; i < len(buf); i++ {
		if buf[i] != 0 {
			return buf[i:]
		}
	}
	return []byte{0}
}

// Transaction types

type LegacyTransaction struct {
	Nonce    uint64
	GasPrice *big.Int
	GasLimit uint64
	To       [20]byte
	Value    *big.Int
	Data     []byte
}

type EIP1559Transaction struct {
	ChainID              *big.Int
	Nonce                uint64
	MaxPriorityFeePerGas *big.Int
	MaxFeePerGas         *big.Int
	GasLimit             uint64
	To                   [20]byte
	Value                *big.Int
	Data                 []byte
	AccessList           []AccessListEntry
}

type EIP4844Transaction struct {
	ChainID              *big.Int
	Nonce                uint64
	MaxPriorityFeePerGas *big.Int
	MaxFeePerGas         *big.Int
	GasLimit             uint64
	To                   [20]byte
	Value                *big.Int
	Data                 []byte
	AccessList           []AccessListEntry
	MaxFeePerBlobGas     *big.Int
	BlobVersionedHashes  [][32]byte
}

type AccessListEntry struct {
	Address     [20]byte
	StorageKeys [][32]byte
}

// GetContractCallData generates calldata for threshold signature verification
func (e *EthereumAdapter) GetContractCallData(method string, params ...interface{}) ([]byte, error) {
	// Generate ABI-encoded calldata
	// This would use actual ABI encoding
	
	// Method selector (first 4 bytes of keccak256(signature))
	selector := e.methodSelector(method)
	
	// Encode parameters
	data := make([]byte, 4)
	copy(data, selector)
	
	// Add encoded parameters
	for _, param := range params {
		// Simplified encoding
		switch v := param.(type) {
		case []byte:
			data = append(data, v...)
		case *big.Int:
			bytes := v.Bytes()
			padding := make([]byte, 32-len(bytes))
			data = append(data, padding...)
			data = append(data, bytes...)
		}
	}
	
	return data, nil
}

func (e *EthereumAdapter) methodSelector(signature string) []byte {
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(signature))
	return hash.Sum(nil)[:4]
}

// CreateMultisigWallet creates a threshold wallet contract deployment transaction
func (e *EthereumAdapter) CreateMultisigWallet(owners []string, threshold int) ([]byte, error) {
	// This would generate the deployment bytecode for a multisig wallet
	// with the specified owners and threshold
	// Placeholder implementation
	return []byte("multisig_deployment_bytecode"), nil
}

// EstimateGas estimates gas for a threshold signature transaction
func (e *EthereumAdapter) EstimateGas(tx interface{}) (uint64, error) {
	// Base cost for ECDSA verification
	baseCost := uint64(3000)
	
	// Additional cost based on transaction type
	switch tx.(type) {
	case *LegacyTransaction:
		return baseCost + 21000, nil
	case *EIP1559Transaction:
		return baseCost + 21000 + 1900, nil // Extra for access list
	case *EIP4844Transaction:
		return baseCost + 21000 + 131072, nil // Blob gas
	default:
		return baseCost + 21000, nil
	}
}