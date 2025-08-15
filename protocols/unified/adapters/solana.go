// Package adapters - Solana adapter for Ed25519 threshold signatures
package adapters

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/luxfi/threshold/pkg/math/curve"
)

// SolanaAdapter implements SignerAdapter for Solana
type SolanaAdapter struct {
	group curve.Curve
}

// NewSolanaAdapter creates a new Solana adapter
func NewSolanaAdapter() *SolanaAdapter {
	return &SolanaAdapter{
		// TODO: Add Ed25519 curve support
		group: curve.Secp256k1{},
	}
}

// Digest computes Solana transaction digest
func (s *SolanaAdapter) Digest(tx interface{}) ([]byte, error) {
	switch v := tx.(type) {
	case *SolanaTransaction:
		return s.digestTransaction(v)
	case *SolanaMessage:
		return s.digestMessage(v)
	case []byte:
		// Raw message bytes
		return v, nil
	default:
		return nil, fmt.Errorf("unsupported Solana transaction type: %T", tx)
	}
}

// digestTransaction computes digest for Solana transaction
func (s *SolanaAdapter) digestTransaction(tx *SolanaTransaction) ([]byte, error) {
	// Serialize message for signing
	message := s.serializeMessage(tx.Message)
	
	// Solana uses the raw message bytes for Ed25519 signing
	// No additional hashing required
	return message, nil
}

// digestMessage computes digest for Solana message
func (s *SolanaAdapter) digestMessage(msg *SolanaMessage) ([]byte, error) {
	return s.serializeMessage(msg), nil
}

// SignEC creates Ed25519 partial signature for Solana
func (s *SolanaAdapter) SignEC(digest []byte, share Share) (PartialSig, error) {
	// This would integrate with FROST protocol for Ed25519
	return &EdDSAPartialSig{
		PartyID: share.ID,
		R:       nil, // Computed in FROST
		Z:       share.Value,
	}, nil
}

// AggregateEC combines Ed25519 partial signatures
func (s *SolanaAdapter) AggregateEC(parts []PartialSig) (FullSig, error) {
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

// Encode formats Ed25519 signature for Solana
func (s *SolanaAdapter) Encode(full FullSig) ([]byte, error) {
	eddsaSig, ok := full.(*EdDSAFullSig)
	if !ok {
		return nil, errors.New("invalid Ed25519 signature")
	}
	
	// Ed25519 signature: R (32 bytes) || z (32 bytes)
	sig := make([]byte, 64)
	
	// Copy R
	rBytes, _ := eddsaSig.R.MarshalBinary()
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

// ValidateConfig validates Solana-specific configuration
func (s *SolanaAdapter) ValidateConfig(config *UnifiedConfig) error {
	if config.SignatureScheme != SignatureEdDSA {
		return errors.New("Solana requires Ed25519 signatures")
	}
	
	// Verify Ed25519 curve
	// TODO: Check for Ed25519 curve when available
	if _, ok := config.Group.(curve.Secp256k1); ok {
		return errors.New("Solana requires Ed25519 curve")
	}
	
	return nil
}

// serializeMessage serializes a Solana message for signing
func (s *SolanaAdapter) serializeMessage(msg *SolanaMessage) []byte {
	var buf []byte
	
	// Number of signatures required
	buf = append(buf, msg.NumRequiredSignatures)
	
	// Number of read-only signed accounts
	buf = append(buf, msg.NumReadonlySignedAccounts)
	
	// Number of read-only unsigned accounts
	buf = append(buf, msg.NumReadonlyUnsignedAccounts)
	
	// Account keys (compact array)
	buf = append(buf, s.encodeCompactArray(len(msg.AccountKeys))...)
	for _, key := range msg.AccountKeys {
		buf = append(buf, key[:]...)
	}
	
	// Recent blockhash
	buf = append(buf, msg.RecentBlockhash[:]...)
	
	// Instructions (compact array)
	buf = append(buf, s.encodeCompactArray(len(msg.Instructions))...)
	for _, inst := range msg.Instructions {
		buf = append(buf, s.serializeInstruction(inst)...)
	}
	
	return buf
}

// serializeInstruction serializes a Solana instruction
func (s *SolanaAdapter) serializeInstruction(inst *SolanaInstruction) []byte {
	var buf []byte
	
	// Program ID index
	buf = append(buf, inst.ProgramIDIndex)
	
	// Account indices (compact array)
	buf = append(buf, s.encodeCompactArray(len(inst.AccountIndices))...)
	buf = append(buf, inst.AccountIndices...)
	
	// Data (compact array)
	buf = append(buf, s.encodeCompactArray(len(inst.Data))...)
	buf = append(buf, inst.Data...)
	
	return buf
}

// encodeCompactArray encodes length in Solana's compact format
func (s *SolanaAdapter) encodeCompactArray(length int) []byte {
	// Compact-u16 encoding
	if length < 0x7f {
		return []byte{byte(length)}
	} else if length < 0x3fff {
		return []byte{
			byte(length&0x7f | 0x80),
			byte(length >> 7),
		}
	} else {
		return []byte{
			byte(length&0x7f | 0x80),
			byte((length>>7)&0x7f | 0x80),
			byte(length >> 14),
		}
	}
}

// Solana transaction structures

type SolanaTransaction struct {
	Signatures []Signature
	Message    *SolanaMessage
}

type SolanaMessage struct {
	NumRequiredSignatures        byte
	NumReadonlySignedAccounts    byte
	NumReadonlyUnsignedAccounts  byte
	AccountKeys                   [][32]byte
	RecentBlockhash              [32]byte
	Instructions                  []*SolanaInstruction
}

type SolanaInstruction struct {
	ProgramIDIndex byte
	AccountIndices []byte
	Data           []byte
}

type Signature [64]byte

// CreateTransferInstruction creates a SOL transfer instruction
func (s *SolanaAdapter) CreateTransferInstruction(from, to [32]byte, lamports uint64) *SolanaInstruction {
	// System program transfer instruction
	// Instruction: 2 (transfer)
	// Args: lamports (u64)
	
	data := []byte{2, 0, 0, 0} // Transfer instruction
	lamportBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(lamportBytes, lamports)
	data = append(data, lamportBytes...)
	
	return &SolanaInstruction{
		ProgramIDIndex: 0, // System program
		AccountIndices: []byte{0, 1}, // From, To
		Data:           data,
	}
}

// CreateTokenTransferInstruction creates SPL token transfer instruction
func (s *SolanaAdapter) CreateTokenTransferInstruction(amount uint64, decimals byte) *SolanaInstruction {
	// SPL Token transfer instruction
	// Instruction: 3 (transfer)
	// Args: amount (u64)
	
	data := []byte{3} // Transfer instruction
	amountBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(amountBytes, amount)
	data = append(data, amountBytes...)
	
	return &SolanaInstruction{
		ProgramIDIndex: 2, // Token program
		AccountIndices: []byte{0, 1, 2}, // Source, Dest, Authority
		Data:           data,
	}
}

// VerifyEd25519Signature verifies an Ed25519 signature on-chain
func (s *SolanaAdapter) VerifyEd25519Signature(pubkey [32]byte, message []byte, signature [64]byte) bool {
	// This would be verified by Solana's ed25519 program
	// Address: Ed25519SigVerify111111111111111111111111111
	return true // Placeholder
}

// ComputeProgramDerivedAddress computes a PDA for threshold wallets
func (s *SolanaAdapter) ComputeProgramDerivedAddress(programID [32]byte, seeds [][]byte) ([32]byte, byte, error) {
	// PDA = hash(seeds || programID || bump)
	// Find bump that produces off-curve point
	
	for bump := byte(255); bump > 0; bump-- {
		h := sha256.New()
		for _, seed := range seeds {
			h.Write(seed)
		}
		h.Write([]byte{bump})
		h.Write([]byte("ProgramDerivedAddress"))
		h.Write(programID[:])
		
		hash := h.Sum(nil)
		
		// Check if point is off-curve (valid PDA)
		// Simplified check - actual would verify Ed25519 curve equation
		if hash[31]&0x80 == 0 {
			var pda [32]byte
			copy(pda[:], hash)
			return pda, bump, nil
		}
	}
	
	return [32]byte{}, 0, errors.New("unable to find valid PDA")
}

// CreateMultisigAccount creates a Solana multisig account
func (s *SolanaAdapter) CreateMultisigAccount(signers [][32]byte, threshold byte) ([]byte, error) {
	// Create multisig account data
	// Format: [threshold, num_signers, signer1, signer2, ...]
	
	data := []byte{threshold, byte(len(signers))}
	for _, signer := range signers {
		data = append(data, signer[:]...)
	}
	
	return data, nil
}

// EstimateComputeUnits estimates compute units for threshold operations
func (s *SolanaAdapter) EstimateComputeUnits(numSignatures int) uint32 {
	// Base cost for Ed25519 verification
	baseCost := uint32(900)
	
	// Additional cost per signature
	perSigCost := uint32(200)
	
	return baseCost + uint32(numSignatures)*perSigCost
}

// GetRentExemptBalance calculates rent-exempt balance for account
func (s *SolanaAdapter) GetRentExemptBalance(dataSize int) uint64 {
	// Solana rent calculation
	// ~2 years of rent = 19.055441478439427 * dataSize + 128
	rentPerByte := uint64(19055441478439427) // In lamports
	baseRent := uint64(128 * 1000000000)     // 128 SOL base
	
	return (rentPerByte*uint64(dataSize))/1000000000000000 + baseRent
}

// SolanaConfig represents Solana-specific configuration
type SolanaConfig struct {
	Cluster          string // mainnet-beta, testnet, devnet
	CommitmentLevel  string // processed, confirmed, finalized
	SkipPreflight    bool
	PreflightCommit  string
	MaxRetries       int
	MinContextSlot   uint64
}

// GetDefaultConfig returns default Solana configuration
func GetDefaultSolanaConfig(cluster string) *SolanaConfig {
	return &SolanaConfig{
		Cluster:         cluster,
		CommitmentLevel: "confirmed",
		SkipPreflight:   false,
		PreflightCommit: "confirmed",
		MaxRetries:      3,
		MinContextSlot:  0,
	}
}