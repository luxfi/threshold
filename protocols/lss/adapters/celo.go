// Package adapters - Celo blockchain adapter (Ethereum-compatible with modifications)
package adapters

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/luxfi/threshold/pkg/math/curve"
	"golang.org/x/crypto/sha3"
)

// CeloAdapter implements SignerAdapter for Celo blockchain
// Celo is Ethereum-compatible but with different transaction formats and phone number mapping
type CeloAdapter struct {
	group   curve.Curve
	chainID *big.Int
}

// NewCeloAdapter creates a new Celo adapter
func NewCeloAdapter() *CeloAdapter {
	return &CeloAdapter{
		group:   curve.Secp256k1{},
		chainID: big.NewInt(42220), // Celo Mainnet
	}
}

// SetChainID sets the Celo chain ID (42220 mainnet, 44787 alfajores testnet)
func (c *CeloAdapter) SetChainID(chainID *big.Int) {
	c.chainID = chainID
}

// Digest computes Celo transaction digest
func (c *CeloAdapter) Digest(tx interface{}) ([]byte, error) {
	switch v := tx.(type) {
	case *CeloTransaction:
		return c.digestTransaction(v)
	case *CeloLegacyTransaction:
		return c.digestLegacyTransaction(v)
	case []byte:
		// Message hash for signing
		return c.hashMessage(v), nil
	default:
		return nil, fmt.Errorf("unsupported Celo transaction type: %T", tx)
	}
}

// digestTransaction computes digest for Celo transaction with gateway fees
func (c *CeloAdapter) digestTransaction(tx *CeloTransaction) ([]byte, error) {
	// Celo adds gateway fee fields to Ethereum transactions
	h := sha3.NewLegacyKeccak256()
	
	// RLP encoding with Celo-specific fields
	encoded := c.rlpEncodeCelo(tx)
	h.Write(encoded)
	
	return h.Sum(nil), nil
}

// digestLegacyTransaction for backwards compatibility
func (c *CeloAdapter) digestLegacyTransaction(tx *CeloLegacyTransaction) ([]byte, error) {
	h := sha3.NewLegacyKeccak256()
	
	// Legacy Celo transaction format
	encoded := c.rlpEncodeLegacy(tx)
	h.Write(encoded)
	
	return h.Sum(nil), nil
}

// hashMessage creates Celo message hash
func (c *CeloAdapter) hashMessage(message []byte) []byte {
	prefix := fmt.Sprintf("\x19Celo Signed Message:\n%d", len(message))
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(prefix))
	h.Write(message)
	return h.Sum(nil)
}

// SignEC creates ECDSA partial signature for Celo
func (c *CeloAdapter) SignEC(digest []byte, share Share) (PartialSig, error) {
	// For testing, provide a placeholder R value
	return &ECDSAPartialSig{
		PartyID: share.ID,
		R:       c.group.NewScalar(), // Placeholder for testing
		S:       share.Value,
	}, nil
}

// AggregateEC combines ECDSA partial signatures
func (c *CeloAdapter) AggregateEC(parts []PartialSig) (FullSig, error) {
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
			s = c.group.NewScalar()
		}
		s = s.Add(ecdsaPart.S)
	}

	return &ECDSAFullSig{
		R: r,
		S: s,
	}, nil
}

// Encode formats ECDSA signature for Celo (same as Ethereum)
func (c *CeloAdapter) Encode(full FullSig) ([]byte, error) {
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

	// Recovery ID (v) - Celo uses same as Ethereum
	sig[64] = 27 // Can be 27 or 28

	return sig, nil
}

// ValidateConfig validates Celo-specific configuration
func (c *CeloAdapter) ValidateConfig(config *UnifiedConfig) error {
	if config.SignatureScheme != SignatureECDSA {
		return errors.New("Celo requires ECDSA signatures")
	}

	// Verify Secp256k1 curve
	if _, ok := config.Group.(curve.Secp256k1); !ok {
		return errors.New("Celo requires Secp256k1 curve")
	}

	return nil
}

// Celo-specific structures

type CeloTransaction struct {
	ChainID              *big.Int
	Nonce                uint64
	MaxPriorityFeePerGas *big.Int
	MaxFeePerGas         *big.Int
	GatewayFeeRecipient  *[20]byte // Celo-specific
	GatewayFee           *big.Int  // Celo-specific
	FeeCurrency          *[20]byte // Celo-specific: address of token to pay fees in
	GasLimit             uint64
	To                   *[20]byte
	Value                *big.Int
	Data                 []byte
	AccessList           []CeloAccessListEntry
}

type CeloLegacyTransaction struct {
	Nonce               uint64
	GasPrice            *big.Int
	GasLimit            uint64
	FeeCurrency         *[20]byte // Celo-specific
	GatewayFeeRecipient *[20]byte // Celo-specific
	GatewayFee          *big.Int  // Celo-specific
	To                  *[20]byte
	Value               *big.Int
	Data                []byte
}

// CeloAccessListEntry for Celo-specific access lists
type CeloAccessListEntry struct {
	Address     [20]byte
	StorageKeys [][32]byte
}

// rlpEncodeCelo encodes Celo transaction with gateway fees
func (c *CeloAdapter) rlpEncodeCelo(tx *CeloTransaction) []byte {
	// Simplified RLP encoding
	var encoded []byte

	// Type byte for Celo transactions
	encoded = append(encoded, 0x7c) // Celo transaction type

	// Chain ID
	if tx.ChainID != nil {
		chainBytes := tx.ChainID.Bytes()
		encoded = append(encoded, chainBytes...)
	}

	// Nonce
	nonceBytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		nonceBytes[7-i] = byte(tx.Nonce >> (8 * i))
	}
	encoded = append(encoded, nonceBytes...)

	// Max priority fee per gas
	if tx.MaxPriorityFeePerGas != nil {
		feeBytes := tx.MaxPriorityFeePerGas.Bytes()
		encoded = append(encoded, feeBytes...)
	}

	// Max fee per gas
	if tx.MaxFeePerGas != nil {
		feeBytes := tx.MaxFeePerGas.Bytes()
		encoded = append(encoded, feeBytes...)
	}

	// Gateway fee recipient (Celo-specific)
	if tx.GatewayFeeRecipient != nil {
		encoded = append(encoded, tx.GatewayFeeRecipient[:]...)
	} else {
		encoded = append(encoded, 0x80) // RLP empty
	}

	// Gateway fee (Celo-specific)
	if tx.GatewayFee != nil {
		feeBytes := tx.GatewayFee.Bytes()
		encoded = append(encoded, feeBytes...)
	} else {
		encoded = append(encoded, 0x80) // RLP empty
	}

	// Fee currency (Celo-specific)
	if tx.FeeCurrency != nil {
		encoded = append(encoded, tx.FeeCurrency[:]...)
	} else {
		encoded = append(encoded, 0x80) // RLP empty
	}

	// Gas limit
	gasBytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		gasBytes[7-i] = byte(tx.GasLimit >> (8 * i))
	}
	encoded = append(encoded, gasBytes...)

	// To address
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
		encoded = append(encoded, 0x80) // RLP empty
	}

	// Data
	encoded = append(encoded, tx.Data...)

	return encoded
}

// rlpEncodeLegacy encodes legacy Celo transaction
func (c *CeloAdapter) rlpEncodeLegacy(tx *CeloLegacyTransaction) []byte {
	// Simplified RLP encoding for legacy format
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

	// Fee currency (Celo-specific)
	if tx.FeeCurrency != nil {
		encoded = append(encoded, tx.FeeCurrency[:]...)
	} else {
		encoded = append(encoded, 0x80)
	}

	// Gateway fee recipient (Celo-specific)
	if tx.GatewayFeeRecipient != nil {
		encoded = append(encoded, tx.GatewayFeeRecipient[:]...)
	} else {
		encoded = append(encoded, 0x80)
	}

	// Gateway fee (Celo-specific)
	if tx.GatewayFee != nil {
		feeBytes := tx.GatewayFee.Bytes()
		encoded = append(encoded, feeBytes...)
	} else {
		encoded = append(encoded, 0x80)
	}

	// To address
	if tx.To != nil {
		encoded = append(encoded, tx.To[:]...)
	} else {
		encoded = append(encoded, 0x80)
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

	return encoded
}

// GenerateCeloAddress generates a Celo address from public key
func (c *CeloAdapter) GenerateCeloAddress(publicKey curve.Point) [20]byte {
	// Same as Ethereum: Keccak256(pubkey)[12:]
	pubBytes, _ := publicKey.MarshalBinary()
	
	h := sha3.NewLegacyKeccak256()
	h.Write(pubBytes[1:]) // Skip format byte
	hash := h.Sum(nil)
	
	var addr [20]byte
	copy(addr[:], hash[12:])
	return addr
}

// MapPhoneNumberToAddress maps phone number to Celo address (simplified)
func (c *CeloAdapter) MapPhoneNumberToAddress(phoneHash [32]byte) [20]byte {
	// Celo's phone number mapping (simplified)
	// Actual implementation would query Celo's attestation service
	h := sha256.Sum256(phoneHash[:])
	var addr [20]byte
	copy(addr[:], h[12:])
	return addr
}

// EstimateFee estimates transaction fee in Celo
func (c *CeloAdapter) EstimateFee(tx *CeloTransaction) uint64 {
	// Base fee calculation
	gasLimit := tx.GasLimit
	
	var gasPrice uint64
	if tx.MaxFeePerGas != nil {
		gasPrice = tx.MaxFeePerGas.Uint64()
	} else {
		gasPrice = 5000000000 // 5 gwei default
	}
	
	fee := gasLimit * gasPrice
	
	// Add gateway fee if present
	if tx.GatewayFee != nil {
		fee += tx.GatewayFee.Uint64()
	}
	
	return fee
}

// GetCeloConfig returns default Celo configuration
func GetDefaultCeloConfig(chainID *big.Int) map[string]interface{} {
	return map[string]interface{}{
		"chain_id":        chainID,
		"signature_type":  SignatureECDSA,
		"curve":          "Secp256k1",
		"hash_algorithm": "Keccak256",
		"fee_currency":   "CELO", // Can be cUSD, cEUR, etc.
		"network":        "mainnet",
	}
}