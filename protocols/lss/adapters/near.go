// Package adapters - NEAR blockchain adapter for Ed25519 threshold signatures
package adapters

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/luxfi/threshold/pkg/math/curve"
	"golang.org/x/crypto/sha3"
)

// NEARAdapter implements SignerAdapter for NEAR Protocol
// NEAR uses Ed25519 for signatures and Borsh serialization
type NEARAdapter struct {
	group     curve.Curve
	networkID string // "mainnet", "testnet", or custom
}

// NewNEARAdapter creates a new NEAR adapter
func NewNEARAdapter(networkID string) *NEARAdapter {
	if networkID == "" {
		networkID = "mainnet"
	}
	return &NEARAdapter{
		// TODO: Add Ed25519 curve support when available
		group:     curve.Secp256k1{}, // Placeholder until Ed25519 is available
		networkID: networkID,
	}
}

// Digest computes NEAR transaction digest
func (n *NEARAdapter) Digest(tx interface{}) ([]byte, error) {
	switch v := tx.(type) {
	case *NEARTransaction:
		return n.digestTransaction(v)
	case *NEARAction:
		return n.digestAction(v)
	case []byte:
		// Raw Borsh bytes
		return n.hashBorsh(v), nil
	default:
		return nil, fmt.Errorf("unsupported NEAR transaction type: %T", tx)
	}
}

// digestTransaction computes digest for NEAR transaction
func (n *NEARAdapter) digestTransaction(tx *NEARTransaction) ([]byte, error) {
	// NEAR uses Borsh serialization with SHA-256
	borsh := n.serializeToBorsh(tx)
	return n.hashBorsh(borsh), nil
}

// digestAction computes digest for NEAR action
func (n *NEARAdapter) digestAction(action *NEARAction) ([]byte, error) {
	borsh := n.serializeActionToBorsh(*action)
	return n.hashBorsh(borsh), nil
}

// hashBorsh computes SHA-256 hash of Borsh data
func (n *NEARAdapter) hashBorsh(data []byte) []byte {
	h := sha3.New256()
	h.Write(data)
	return h.Sum(nil)
}

// SignEC creates Ed25519 partial signature for NEAR
func (n *NEARAdapter) SignEC(digest []byte, share Share) (PartialSig, error) {
	// This would integrate with FROST protocol for Ed25519
	// For testing, provide a placeholder R value
	return &EdDSAPartialSig{
		PartyID: share.ID,
		R:       n.group.NewBasePoint(), // Placeholder for testing
		Z:       share.Value,
	}, nil
}

// AggregateEC combines Ed25519 partial signatures
func (n *NEARAdapter) AggregateEC(parts []PartialSig) (FullSig, error) {
	if len(parts) == 0 {
		return nil, errors.New("no partial signatures")
	}

	var r curve.Point
	z := n.group.NewScalar()

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

// Encode formats Ed25519 signature for NEAR
func (n *NEARAdapter) Encode(full FullSig) ([]byte, error) {
	eddsaSig, ok := full.(*EdDSAFullSig)
	if !ok {
		return nil, errors.New("invalid Ed25519 signature")
	}

	// Ed25519 signature: R (32 bytes) || z (32 bytes)
	sig := make([]byte, 64)

	// Copy R
	rBytes, _ := eddsaSig.R.MarshalBinary()
	// Skip format byte if present
	if len(rBytes) == 33 && (rBytes[0] == 0x02 || rBytes[0] == 0x03 || rBytes[0] == 0x04) {
		rBytes = rBytes[1:]
	}
	if len(rBytes) != 32 {
		return nil, fmt.Errorf("invalid R length: %d", len(rBytes))
	}
	copy(sig[:32], rBytes)

	// Copy z
	zBytes, _ := eddsaSig.Z.MarshalBinary()
	if len(zBytes) > 32 {
		return nil, fmt.Errorf("invalid z length: %d", len(zBytes))
	}
	copy(sig[32+(32-len(zBytes)):], zBytes)

	return sig, nil
}

// ValidateConfig validates NEAR-specific configuration
func (n *NEARAdapter) ValidateConfig(config *UnifiedConfig) error {
	if config.SignatureScheme != SignatureEdDSA {
		return errors.New("NEAR requires Ed25519 signatures")
	}

	// Verify Ed25519 curve
	// TODO: Check for Ed25519 curve when available

	return nil
}

// NEAR-specific structures

type NEARTransaction struct {
	SignerID   string
	PublicKey  PublicKey
	Nonce      uint64
	ReceiverID string
	BlockHash  [32]byte
	Actions    []NEARAction
}

type PublicKey struct {
	KeyType KeyType
	Data    [32]byte
}

type KeyType byte

const (
	ED25519KeyType KeyType = 0
	SECP256K1KeyType KeyType = 1
)

type NEARAction interface {
	Type() ActionType
}

type ActionType byte

const (
	CreateAccount ActionType = iota
	DeployContract
	FunctionCall
	Transfer
	Stake
	AddKey
	DeleteKey
	DeleteAccount
)

type TransferAction struct {
	Deposit NEARAmount
}

func (t *TransferAction) Type() ActionType { return Transfer }

type FunctionCallAction struct {
	MethodName string
	Args       []byte
	Gas        uint64
	Deposit    NEARAmount
}

func (f *FunctionCallAction) Type() ActionType { return FunctionCall }

type DeployContractAction struct {
	Code []byte
}

func (d *DeployContractAction) Type() ActionType { return DeployContract }

type StakeAction struct {
	Stake     NEARAmount
	PublicKey PublicKey
}

func (s *StakeAction) Type() ActionType { return Stake }

type AddKeyAction struct {
	PublicKey   PublicKey
	AccessKey   AccessKey
}

func (a *AddKeyAction) Type() ActionType { return AddKey }

type AccessKey struct {
	Nonce      uint64
	Permission Permission
}

type Permission interface {
	Type() PermissionType
}

type PermissionType byte

const (
	FullAccess PermissionType = iota
	FunctionCallPermission
)

// FullAccessPermission represents full access
type FullAccessPermission struct{}

func (f *FullAccessPermission) Type() PermissionType { return FullAccess }

// FunctionCallPermissionData represents function call permission
type FunctionCallPermissionData struct {
	Allowance   *NEARAmount
	ReceiverID  string
	MethodNames []string
}

func (f *FunctionCallPermissionData) Type() PermissionType { return FunctionCallPermission }

type NEARAmount struct {
	Amount [16]byte // 128-bit integer
}

// serializeToBorsh serializes a NEAR transaction to Borsh format
func (n *NEARAdapter) serializeToBorsh(tx *NEARTransaction) []byte {
	// Simplified Borsh serialization
	// Actual implementation would follow NEAR's Borsh specification
	var borsh []byte

	// Signer ID (string length + data)
	signerBytes := []byte(tx.SignerID)
	lenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBytes, uint32(len(signerBytes)))
	borsh = append(borsh, lenBytes...)
	borsh = append(borsh, signerBytes...)

	// Public key
	borsh = append(borsh, byte(tx.PublicKey.KeyType))
	borsh = append(borsh, tx.PublicKey.Data[:]...)

	// Nonce
	nonceBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(nonceBytes, tx.Nonce)
	borsh = append(borsh, nonceBytes...)

	// Receiver ID
	receiverBytes := []byte(tx.ReceiverID)
	lenBytes = make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBytes, uint32(len(receiverBytes)))
	borsh = append(borsh, lenBytes...)
	borsh = append(borsh, receiverBytes...)

	// Block hash
	borsh = append(borsh, tx.BlockHash[:]...)

	// Actions count
	actionsLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(actionsLen, uint32(len(tx.Actions)))
	borsh = append(borsh, actionsLen...)

	// Serialize each action
	for _, action := range tx.Actions {
		borsh = append(borsh, n.serializeActionToBorsh(action)...)
	}

	return borsh
}

// serializeActionToBorsh serializes a NEAR action
func (n *NEARAdapter) serializeActionToBorsh(action NEARAction) []byte {
	var borsh []byte

	// Action type
	borsh = append(borsh, byte(action.Type()))

	// Action-specific data (simplified)
	switch a := action.(type) {
	case *TransferAction:
		borsh = append(borsh, a.Deposit.Amount[:]...)
	case *FunctionCallAction:
		// Method name
		methodBytes := []byte(a.MethodName)
		lenBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(lenBytes, uint32(len(methodBytes)))
		borsh = append(borsh, lenBytes...)
		borsh = append(borsh, methodBytes...)
		
		// Args
		lenBytes = make([]byte, 4)
		binary.LittleEndian.PutUint32(lenBytes, uint32(len(a.Args)))
		borsh = append(borsh, lenBytes...)
		borsh = append(borsh, a.Args...)
		
		// Gas
		gasBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(gasBytes, a.Gas)
		borsh = append(borsh, gasBytes...)
		
		// Deposit
		borsh = append(borsh, a.Deposit.Amount[:]...)
	}

	return borsh
}

// GenerateNEARAddress generates a NEAR account ID from public key
func (n *NEARAdapter) GenerateNEARAddress(publicKey [32]byte, accountID string) string {
	// NEAR uses human-readable account IDs, not derived from public keys
	// Format: accountname.near or accountname.testnet
	if accountID == "" {
		// Generate a default account ID from public key (for testing)
		h := sha3.New256()
		h.Write(publicKey[:])
		hash := h.Sum(nil)
		accountID = fmt.Sprintf("%x", hash[:8])
	}
	
	// Add network suffix
	switch n.networkID {
	case "mainnet":
		return accountID + ".near"
	case "testnet":
		return accountID + ".testnet"
	default:
		return accountID
	}
}

// EstimateGas estimates gas for NEAR transaction
func (n *NEARAdapter) EstimateGas(tx *NEARTransaction) uint64 {
	// Base cost in TGas (10^12 gas units)
	baseCost := uint64(1_000_000_000_000)
	
	// Add cost per action
	actionCost := uint64(0)
	for _, action := range tx.Actions {
		switch action.Type() {
		case Transfer:
			actionCost += 115_000_000_000
		case FunctionCall:
			actionCost += 2_500_000_000_000
		case DeployContract:
			actionCost += 10_000_000_000_000
		default:
			actionCost += 1_000_000_000_000
		}
	}
	
	return baseCost + actionCost
}

// GetNEARConfig returns default NEAR configuration
func GetDefaultNEARConfig(networkID string) map[string]interface{} {
	return map[string]interface{}{
		"network_id":      networkID,
		"signature_type":  SignatureEdDSA,
		"curve":          "Ed25519",
		"hash_algorithm": "SHA3-256",
		"serialization":  "Borsh",
		"rpc_url":        fmt.Sprintf("https://rpc.%s.near.org", networkID),
	}
}