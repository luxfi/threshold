// Package adapters - Sui blockchain adapter for Ed25519 threshold signatures
package adapters

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/luxfi/threshold/pkg/math/curve"
	"golang.org/x/crypto/blake2b"
)

// SuiAdapter implements SignerAdapter for Sui blockchain
// Sui uses Ed25519 for signatures and BCS (Binary Canonical Serialization)
type SuiAdapter struct {
	group     curve.Curve
	intentApp byte // 0x00 for transaction, 0x01 for personal message
}

// NewSuiAdapter creates a new Sui adapter
func NewSuiAdapter() *SuiAdapter {
	return &SuiAdapter{
		// TODO: Add Ed25519 curve support when available
		group:     curve.Secp256k1{}, // Placeholder until Ed25519 is available
		intentApp: 0x00,              // Transaction by default
	}
}

// Digest computes Sui transaction digest using Blake2b
func (s *SuiAdapter) Digest(tx interface{}) ([]byte, error) {
	switch v := tx.(type) {
	case *SuiTransaction:
		return s.digestTransaction(v)
	case *SuiProgrammableTransaction:
		return s.digestProgrammable(v)
	case []byte:
		// Raw BCS bytes
		return s.hashWithIntent(v), nil
	default:
		return nil, fmt.Errorf("unsupported Sui transaction type: %T", tx)
	}
}

// digestTransaction computes digest for Sui transaction
func (s *SuiAdapter) digestTransaction(tx *SuiTransaction) ([]byte, error) {
	// Sui uses Intent || BCS(TransactionData) for signing
	bcs := s.serializeToBCS(tx)
	return s.hashWithIntent(bcs), nil
}

// digestProgrammable computes digest for programmable transaction
func (s *SuiAdapter) digestProgrammable(tx *SuiProgrammableTransaction) ([]byte, error) {
	bcs := s.serializeProgrammableToBCS(tx)
	return s.hashWithIntent(bcs), nil
}

// hashWithIntent computes Blake2b-256 hash with intent prefix
func (s *SuiAdapter) hashWithIntent(data []byte) []byte {
	// Intent structure: [IntentScope(1) || IntentVersion(1) || IntentApp(1)]
	intent := []byte{
		0x00, // IntentScope: TransactionData
		0x00, // IntentVersion: V0
		s.intentApp,
	}

	h, _ := blake2b.New256(nil)
	h.Write(intent)
	h.Write(data)
	return h.Sum(nil)
}

// SignEC creates Ed25519 partial signature for Sui
func (s *SuiAdapter) SignEC(digest []byte, share Share) (PartialSig, error) {
	// This would integrate with FROST protocol for Ed25519
	// For testing, provide a placeholder R value
	return &EdDSAPartialSig{
		PartyID: share.ID,
		R:       s.group.NewBasePoint(), // Placeholder for testing
		Z:       share.Value,
	}, nil
}

// AggregateEC combines Ed25519 partial signatures
func (s *SuiAdapter) AggregateEC(parts []PartialSig) (FullSig, error) {
	if len(parts) == 0 {
		return nil, errors.New("no partial signatures")
	}

	var r curve.Point
	z := s.group.NewScalar()

	for _, part := range parts {
		eddsaPart, ok := part.(*EdDSAPartialSig)
		if !ok {
			return nil, errors.New("invalid Ed25519 partial signature")
		}

		if r == nil && eddsaPart.R != nil {
			r = eddsaPart.R
		}

		z = z.Add(eddsaPart.Z)
	}

	return &EdDSAFullSig{
		R: r,
		Z: z,
	}, nil
}

// Encode formats Ed25519 signature for Sui with flag byte
func (s *SuiAdapter) Encode(full FullSig) ([]byte, error) {
	eddsaSig, ok := full.(*EdDSAFullSig)
	if !ok {
		return nil, errors.New("invalid Ed25519 signature")
	}

	// Sui signature format: Flag (1) || Signature (64) || PublicKey (32)
	// Flag: 0x00 for Ed25519
	sig := make([]byte, 97) // 1 + 64 + 32
	sig[0] = 0x00           // Ed25519 flag

	// Copy R (32 bytes)
	rBytes, _ := eddsaSig.R.MarshalBinary()
	// Skip format byte if present
	if len(rBytes) == 33 && (rBytes[0] == 0x02 || rBytes[0] == 0x03 || rBytes[0] == 0x04) {
		rBytes = rBytes[1:]
	}
	if len(rBytes) != 32 {
		return nil, fmt.Errorf("invalid R length: %d", len(rBytes))
	}
	copy(sig[1:33], rBytes)

	// Copy z (32 bytes)
	zBytes, _ := eddsaSig.Z.MarshalBinary()
	if len(zBytes) > 32 {
		return nil, fmt.Errorf("invalid z length: %d", len(zBytes))
	}
	copy(sig[33+(32-len(zBytes)):65], zBytes)

	// Note: Public key would be appended here in production
	// For now, leaving zeros as placeholder

	return sig[:65], nil // Return without pubkey for now
}

// ValidateConfig validates Sui-specific configuration
func (s *SuiAdapter) ValidateConfig(config *UnifiedConfig) error {
	if config.SignatureScheme != SignatureEdDSA {
		return errors.New("Sui requires Ed25519 signatures")
	}

	// Verify Ed25519 curve
	// TODO: Check for Ed25519 curve when available

	return nil
}

// Sui-specific structures

type SuiTransaction struct {
	Kind       TransactionKind
	Sender     SuiAddress
	GasPayment *GasPayment
	GasPrice   uint64
	GasBudget  uint64
	Expiration *TransactionExpiration
}

type TransactionKind interface {
	Type() TransactionType
}

type TransactionType byte

const (
	TransferObject TransactionType = iota
	Publish
	MoveCall
	TransferSui
	ChangeEpoch
	Pay
	PaySui
	PayAllSui
	ProgrammableTransaction
)

type SuiAddress [32]byte

type GasPayment struct {
	Objects []ObjectRef
	Owner   SuiAddress
	Price   uint64
	Budget  uint64
}

type ObjectRef struct {
	ObjectID ObjectID
	Version  uint64
	Digest   ObjectDigest
}

type ObjectID [32]byte
type ObjectDigest [32]byte

type TransactionExpiration struct {
	Epoch uint64
}

type SuiProgrammableTransaction struct {
	Inputs   []CallArg
	Commands []Command
}

type CallArg interface {
	Type() CallArgType
}

type CallArgType byte

const (
	PureArg CallArgType = iota
	ObjectArg
	MoveVecArg
)

type Command interface {
	Type() CommandType
}

type CommandType byte

const (
	MoveCallCommand CommandType = iota
	TransferObjectsCommand
	SplitCoinsCommand
	MergeCoinsCommand
	PublishCommand
	MakeMoveVecCommand
	UpgradeCommand
)

// serializeToBCS serializes a Sui transaction to BCS format
func (s *SuiAdapter) serializeToBCS(tx *SuiTransaction) []byte {
	// Simplified BCS serialization
	// Actual implementation would follow Sui's BCS specification
	var bcs []byte

	// Transaction kind
	bcs = append(bcs, byte(0)) // Placeholder for kind

	// Sender address
	bcs = append(bcs, tx.Sender[:]...)

	// Gas payment
	if tx.GasPayment != nil {
		bcs = append(bcs, 1) // Has gas payment
		bcs = append(bcs, s.serializeGasPayment(tx.GasPayment)...)
	} else {
		bcs = append(bcs, 0) // No gas payment
	}

	// Gas price
	priceBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(priceBytes, tx.GasPrice)
	bcs = append(bcs, priceBytes...)

	// Gas budget
	budgetBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(budgetBytes, tx.GasBudget)
	bcs = append(bcs, budgetBytes...)

	// Expiration
	if tx.Expiration != nil {
		bcs = append(bcs, 1) // Has expiration
		epochBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(epochBytes, tx.Expiration.Epoch)
		bcs = append(bcs, epochBytes...)
	} else {
		bcs = append(bcs, 0) // No expiration
	}

	return bcs
}

// serializeProgrammableToBCS serializes programmable transaction
func (s *SuiAdapter) serializeProgrammableToBCS(tx *SuiProgrammableTransaction) []byte {
	var bcs []byte

	// Inputs count (ULEB128)
	bcs = append(bcs, s.encodeULEB128(uint64(len(tx.Inputs)))...)

	// Serialize inputs
	for _, input := range tx.Inputs {
		bcs = append(bcs, byte(input.Type()))
		// Serialize input data (simplified)
	}

	// Commands count
	bcs = append(bcs, s.encodeULEB128(uint64(len(tx.Commands)))...)

	// Serialize commands
	for _, cmd := range tx.Commands {
		bcs = append(bcs, byte(cmd.Type()))
		// Serialize command data (simplified)
	}

	return bcs
}

// serializeGasPayment serializes gas payment
func (s *SuiAdapter) serializeGasPayment(gas *GasPayment) []byte {
	var data []byte

	// Objects count
	data = append(data, byte(len(gas.Objects)))

	// Object refs
	for _, obj := range gas.Objects {
		data = append(data, obj.ObjectID[:]...)
		versionBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(versionBytes, obj.Version)
		data = append(data, versionBytes...)
		data = append(data, obj.Digest[:]...)
	}

	// Owner
	data = append(data, gas.Owner[:]...)

	// Price and budget
	priceBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(priceBytes, gas.Price)
	data = append(data, priceBytes...)

	budgetBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(budgetBytes, gas.Budget)
	data = append(data, budgetBytes...)

	return data
}

// encodeULEB128 encodes unsigned integer in ULEB128 format
func (s *SuiAdapter) encodeULEB128(n uint64) []byte {
	var result []byte
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n != 0 {
			b |= 0x80
		}
		result = append(result, b)
		if n == 0 {
			break
		}
	}
	return result
}

// GenerateSuiAddress generates a Sui address from public key
func (s *SuiAdapter) GenerateSuiAddress(publicKey [32]byte) SuiAddress {
	// Sui address = Blake2b-256(flag || pubkey || 0x00)
	// flag: 0x00 for Ed25519
	h, _ := blake2b.New256(nil)
	h.Write([]byte{0x00}) // Ed25519 flag
	h.Write(publicKey[:])
	h.Write([]byte{0x00}) // Single signature scheme

	hash := h.Sum(nil)
	var addr SuiAddress
	copy(addr[:], hash)
	return addr
}

// CreateTransferTransaction creates a simple transfer transaction
func (s *SuiAdapter) CreateTransferTransaction(from, to SuiAddress, amount uint64) *SuiTransaction {
	return &SuiTransaction{
		Sender:    from,
		GasPrice:  1000,
		GasBudget: 10000000,
	}
}

// EstimateGas estimates gas for Sui transaction
func (s *SuiAdapter) EstimateGas(tx *SuiTransaction) uint64 {
	// Base computation cost
	baseCost := uint64(1000)

	// Transaction size cost
	txSize := len(s.serializeToBCS(tx))
	sizeCost := uint64(txSize * 10)

	// Storage cost (if creating objects)
	storageCost := uint64(0)

	return baseCost + sizeCost + storageCost
}

// GetSuiConfig returns default Sui configuration
func GetDefaultSuiConfig() map[string]interface{} {
	return map[string]interface{}{
		"signature_type": SignatureEdDSA,
		"curve":          "Ed25519",
		"hash_algorithm": "Blake2b-256",
		"serialization":  "BCS",
		"intent_version": 0,
	}
}
