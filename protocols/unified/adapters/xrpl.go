// Package adapters provides chain-specific implementations for threshold signatures
package adapters

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/luxfi/threshold/pkg/math/curve"
)

// XRPLHashPrefix defines XRPL transaction hash prefixes
type XRPLHashPrefix [4]byte

var (
	// STX is the single-signing prefix (0x53545800)
	STX = XRPLHashPrefix{0x53, 0x54, 0x58, 0x00}
	
	// SMT is the multi-signing prefix (0x534D5400)
	SMT = XRPLHashPrefix{0x53, 0x4D, 0x54, 0x00}
	
	// Ed25519Prefix is the XRPL Ed25519 public key prefix
	Ed25519Prefix = byte(0xED)
)

// XRPLAdapter implements SignerAdapter for XRPL
type XRPLAdapter struct {
	sigType   SignatureType
	multiSign bool // true for multi-signing, false for threshold
	group     curve.Curve
}

// NewXRPLAdapter creates a new XRPL adapter
func NewXRPLAdapter(sigType SignatureType, multiSign bool) *XRPLAdapter {
	var group curve.Curve
	switch sigType {
	case SignatureECDSA:
		group = curve.Secp256k1{}
	case SignatureEdDSA:
		// TODO: Add Ed25519 curve support when available
		group = curve.Secp256k1{} // Placeholder until Ed25519 is available
	default:
		panic("unsupported signature type for XRPL")
	}
	
	return &XRPLAdapter{
		sigType:   sigType,
		multiSign: multiSign,
		group:     group,
	}
}

// Digest computes XRPL transaction digest with appropriate prefix
func (x *XRPLAdapter) Digest(tx interface{}) ([]byte, error) {
	txBlob, ok := tx.([]byte)
	if !ok {
		return nil, errors.New("XRPL: tx must be []byte (binary-serialized transaction)")
	}
	
	// Select prefix based on signing mode
	var prefix XRPLHashPrefix
	if x.multiSign {
		prefix = SMT
	} else {
		prefix = STX
	}
	
	// Compute SHA-512Half (first 256 bits of SHA-512)
	h := sha512.New()
	h.Write(prefix[:])
	h.Write(txBlob)
	fullHash := h.Sum(nil)
	
	// Return first 32 bytes (256 bits)
	return fullHash[:32], nil
}

// SignEC performs threshold signing for XRPL
func (x *XRPLAdapter) SignEC(digest []byte, share Share) (PartialSig, error) {
	switch x.sigType {
	case SignatureECDSA:
		return x.signECDSA(digest, share)
	case SignatureEdDSA:
		return x.signEd25519(digest, share)
	default:
		return nil, fmt.Errorf("unsupported signature type: %v", x.sigType)
	}
}

// signECDSA creates ECDSA partial signature for XRPL
func (x *XRPLAdapter) signECDSA(digest []byte, share Share) (PartialSig, error) {
	// This would integrate with CMP protocol
	// Return partial signature share
	return &ECDSAPartialSig{
		PartyID: share.ID,
		R:       nil, // Would be computed in CMP
		S:       share.Value,
	}, nil
}

// signEd25519 creates Ed25519 partial signature for XRPL
func (x *XRPLAdapter) signEd25519(digest []byte, share Share) (PartialSig, error) {
	// This would integrate with FROST protocol
	// Return partial signature share
	return &EdDSAPartialSig{
		PartyID: share.ID,
		R:       nil, // Would be computed in FROST
		Z:       share.Value,
	}, nil
}

// AggregateEC combines partial signatures
func (x *XRPLAdapter) AggregateEC(parts []PartialSig) (FullSig, error) {
	if len(parts) == 0 {
		return nil, errors.New("no partial signatures to aggregate")
	}
	
	switch x.sigType {
	case SignatureECDSA:
		return x.aggregateECDSA(parts)
	case SignatureEdDSA:
		return x.aggregateEd25519(parts)
	default:
		return nil, fmt.Errorf("unsupported signature type: %v", x.sigType)
	}
}

// aggregateECDSA combines ECDSA partial signatures with low-S normalization
func (x *XRPLAdapter) aggregateECDSA(parts []PartialSig) (FullSig, error) {
	// Aggregate R and S values from partial signatures
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
			s = x.group.NewScalar()
		}
		s = s.Add(ecdsaPart.S)
	}
	
	// Enforce low-S normalization for XRPL canonical signatures
	s = x.normalizeLowS(s)
	
	return &ECDSAFullSig{
		R: r,
		S: s,
	}, nil
}

// aggregateEd25519 combines Ed25519 partial signatures
func (x *XRPLAdapter) aggregateEd25519(parts []PartialSig) (FullSig, error) {
	// Aggregate R and z values from partial signatures
	var r curve.Point
	z := x.group.NewScalar()
	
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

// Encode formats signature for XRPL wire format
func (x *XRPLAdapter) Encode(full FullSig) ([]byte, error) {
	switch x.sigType {
	case SignatureECDSA:
		return x.encodeECDSA(full)
	case SignatureEdDSA:
		return x.encodeEd25519(full)
	default:
		return nil, fmt.Errorf("unsupported signature type: %v", x.sigType)
	}
}

// encodeECDSA encodes ECDSA signature in DER format for XRPL
func (x *XRPLAdapter) encodeECDSA(full FullSig) ([]byte, error) {
	ecdsaSig, ok := full.(*ECDSAFullSig)
	if !ok {
		return nil, errors.New("invalid ECDSA full signature")
	}
	
	// Convert to DER format
	rBytes, _ := ecdsaSig.R.MarshalBinary()
	sBytes, _ := ecdsaSig.S.MarshalBinary()
	
	// DER encoding
	der := make([]byte, 0, 72)
	der = append(der, 0x30) // SEQUENCE tag
	
	// Calculate total length
	rLen := len(rBytes)
	sLen := len(sBytes)
	if rBytes[0]&0x80 != 0 {
		rLen++ // Need padding for positive number
	}
	if sBytes[0]&0x80 != 0 {
		sLen++ // Need padding for positive number
	}
	
	totalLen := 2 + rLen + 2 + sLen
	der = append(der, byte(totalLen))
	
	// Encode R
	der = append(der, 0x02, byte(rLen))
	if rBytes[0]&0x80 != 0 {
		der = append(der, 0x00)
	}
	der = append(der, rBytes...)
	
	// Encode S
	der = append(der, 0x02, byte(sLen))
	if sBytes[0]&0x80 != 0 {
		der = append(der, 0x00)
	}
	der = append(der, sBytes...)
	
	return der, nil
}

// encodeEd25519 encodes Ed25519 signature for XRPL
func (x *XRPLAdapter) encodeEd25519(full FullSig) ([]byte, error) {
	eddsaSig, ok := full.(*EdDSAFullSig)
	if !ok {
		return nil, errors.New("invalid Ed25519 full signature")
	}
	
	// Ed25519 signature is R || z (64 bytes total)
	sig := make([]byte, 64)
	
	// Copy R (32 bytes)
	rBytes, _ := eddsaSig.R.MarshalBinary()
	if len(rBytes) != 32 {
		return nil, fmt.Errorf("invalid R length: %d", len(rBytes))
	}
	copy(sig[:32], rBytes)
	
	// Copy z (32 bytes)
	zBytes, _ := eddsaSig.Z.MarshalBinary()
	if len(zBytes) > 32 {
		return nil, fmt.Errorf("invalid z length: %d", len(zBytes))
	}
	// Pad z if necessary
	copy(sig[32+(32-len(zBytes)):], zBytes)
	
	return sig, nil
}

// normalizeLowS ensures S value is in the lower half of the order
func (x *XRPLAdapter) normalizeLowS(s curve.Scalar) curve.Scalar {
	// Get the curve order
	orderModulus := x.group.Order()
	orderBig := orderModulus.Big()
	halfOrder := new(big.Int).Div(orderBig, big.NewInt(2))
	
	// Convert s to big.Int
	sBytes, _ := s.MarshalBinary()
	sInt := new(big.Int).SetBytes(sBytes)
	
	// If s > n/2, set s = n - s
	if sInt.Cmp(halfOrder) > 0 {
		sInt = new(big.Int).Sub(orderBig, sInt)
		// Convert back to scalar
		sNat := sInt.Bytes()
		s = x.group.NewScalar()
		s.UnmarshalBinary(sNat)
	}
	
	return s
}

// FormatPublicKey formats public key for XRPL with appropriate prefix
func (x *XRPLAdapter) FormatPublicKey(pubKey curve.Point) string {
	keyBytes, _ := pubKey.MarshalBinary()
	
	if x.sigType == SignatureEdDSA {
		// Add 0xED prefix for Ed25519 keys
		prefixedKey := make([]byte, len(keyBytes)+1)
		prefixedKey[0] = Ed25519Prefix
		copy(prefixedKey[1:], keyBytes)
		return hex.EncodeToString(prefixedKey)
	}
	
	// ECDSA keys use standard compressed format
	return hex.EncodeToString(keyBytes)
}

// ValidateConfig checks if the configuration is valid for XRPL
func (x *XRPLAdapter) ValidateConfig(config *UnifiedConfig) error {
	// XRPL-specific validation
	if config.SignatureScheme != x.sigType {
		return fmt.Errorf("config signature type %v doesn't match adapter type %v", 
			config.SignatureScheme, x.sigType)
	}
	
	// Check threshold bounds for XRPL
	if config.Threshold < 1 || config.Threshold > 8 {
		return fmt.Errorf("XRPL supports threshold 1-8, got %d", config.Threshold)
	}
	
	// Verify all verification shares are present
	for _, pid := range config.PartyIDs {
		if _, exists := config.VerificationShares[pid]; !exists {
			return fmt.Errorf("missing verification share for party %s", pid)
		}
	}
	
	return nil
}

// GetSignerListEntry creates XRPL SignerListSet entry for this configuration
func (x *XRPLAdapter) GetSignerListEntry(config *UnifiedConfig, weight uint16) map[string]interface{} {
	signers := make([]map[string]interface{}, 0, len(config.PartyIDs))
	
	for _, pid := range config.PartyIDs {
		verificationShare, ok := config.VerificationShares[pid].(curve.Point)
		if !ok {
			// Skip if not a curve point
			continue
		}
		signers = append(signers, map[string]interface{}{
			"SignerEntry": map[string]interface{}{
				"Account":      x.deriveXRPLAddress(verificationShare),
				"SignerWeight": weight,
			},
		})
	}
	
	return map[string]interface{}{
		"SignerQuorum":  config.Threshold * int(weight),
		"SignerEntries": signers,
	}
}

// deriveXRPLAddress derives XRPL address from public key
func (x *XRPLAdapter) deriveXRPLAddress(pubKey curve.Point) string {
	// This would implement full XRPL address derivation
	// RIPEMD160(SHA256(publicKey)) with Base58Check encoding
	// For now, return placeholder
	return "rXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
}

// XRPLTransaction represents a simplified XRPL transaction
type XRPLTransaction struct {
	Account         string
	TransactionType string
	Destination     string
	Amount          string
	Fee             string
	Sequence        uint32
	SigningPubKey   string
	TxnSignature    string
}

// SerializeTxBlob serializes an XRPL transaction to binary format
func SerializeTxBlob(tx *XRPLTransaction) ([]byte, error) {
	// This would implement full XRPL binary serialization
	// Following the XRPL binary codec specification
	// For now, return a placeholder
	return []byte("serialized_tx_blob"), nil
}

// ParseSignedTransaction parses a signed XRPL transaction
func ParseSignedTransaction(blob []byte, signature []byte) (*XRPLTransaction, error) {
	// This would parse the binary blob and attach the signature
	// For now, return a placeholder
	return &XRPLTransaction{
		TxnSignature: hex.EncodeToString(signature),
	}, nil
}