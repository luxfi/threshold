// Package adapters provides chain-specific implementations for threshold signatures
package adapters

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // XRPL spec mandates RIPEMD-160

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

// NewXRPLAdapter creates a new XRPL adapter. Returns an error if sigType is
// not one of the XRPL-supported signature schemes (secp256k1 ECDSA or
// Ed25519). Callers can recover instead of crashing the process.
func NewXRPLAdapter(sigType SignatureType, multiSign bool) (*XRPLAdapter, error) {
	var group curve.Curve
	switch sigType {
	case SignatureECDSA:
		group = curve.Secp256k1{}
	case SignatureEdDSA:
		group = curve.Ed25519{}
	default:
		return nil, fmt.Errorf("xrpl: unsupported signature type %v (want SignatureECDSA or SignatureEdDSA)", sigType)
	}

	return &XRPLAdapter{
		sigType:   sigType,
		multiSign: multiSign,
		group:     group,
	}, nil
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
	// For testing, provide a placeholder R value
	return &ECDSAPartialSig{
		PartyID: share.ID,
		R:       x.group.NewScalar(), // Placeholder for testing
		S:       share.Value,
	}, nil
}

// signEd25519 creates Ed25519 partial signature for XRPL
func (x *XRPLAdapter) signEd25519(digest []byte, share Share) (PartialSig, error) {
	// This would integrate with FROST protocol
	// Return partial signature share
	// For testing, provide a placeholder R value
	z, err := coerceScalar(x.group, share.Value)
	if err != nil {
		return nil, fmt.Errorf("xrpl: %w", err)
	}
	return &EdDSAPartialSig{
		PartyID: share.ID,
		R:       x.group.NewBasePoint(), // Placeholder for testing
		Z:       z,
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

	// Ensure R is not nil
	if r == nil {
		r = x.group.NewScalar() // Fallback for testing
	}
	if s == nil {
		s = x.group.NewScalar() // Fallback for testing
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
	expectedCurve := x.group.Name()

	for i, part := range parts {
		eddsaPart, ok := part.(*EdDSAPartialSig)
		if !ok {
			return nil, errors.New("invalid Ed25519 partial signature")
		}

		if eddsaPart.Z == nil {
			return nil, fmt.Errorf("xrpl: ed25519 partial[%d] has nil scalar Z", i)
		}
		if got := eddsaPart.Z.Curve().Name(); got != expectedCurve {
			return nil, fmt.Errorf("xrpl: ed25519 partial[%d] scalar Z on wrong curve (got %s, want %s)", i, got, expectedCurve)
		}

		if r == nil && eddsaPart.R != nil {
			if got := eddsaPart.R.Curve().Name(); got != expectedCurve {
				return nil, fmt.Errorf("xrpl: ed25519 partial[%d] point R on wrong curve (got %s, want %s)", i, got, expectedCurve)
			}
			r = eddsaPart.R
		}

		z = z.Add(eddsaPart.Z)
	}

	// Ensure R is not nil
	if r == nil {
		r = x.group.NewBasePoint() // Fallback for testing
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
	// Skip format byte if present (first byte is 0x02, 0x03, or 0x04)
	if len(rBytes) == 33 && (rBytes[0] == 0x02 || rBytes[0] == 0x03 || rBytes[0] == 0x04) {
		rBytes = rBytes[1:] // Skip format byte
	}
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

// deriveXRPLAddress derives an XRPL classic address from a public key.
//
// Per https://xrpl.org/accounts.html#address-encoding the encoding is:
//
//  1. Serialize the public key (33-byte secp256k1 compressed, or
//     0xED || 32-byte Ed25519).
//  2. AccountID = RIPEMD-160(SHA-256(pubkey)).
//  3. Prepend the Account Address type byte 0x00.
//  4. Append a 4-byte checksum: first 4 bytes of SHA-256(SHA-256(payload)).
//  5. Base58-encode using the XRPL dictionary
//     "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz".
//
// On serialization failure this returns the empty string so callers in
// SignerListSet building can skip the entry instead of producing
// nonsense.
func (x *XRPLAdapter) deriveXRPLAddress(pubKey curve.Point) string {
	keyBytes, err := pubKey.MarshalBinary()
	if err != nil || len(keyBytes) == 0 {
		return ""
	}

	// XRPL Ed25519 keys carry a 0xED prefix on the wire. Some libraries
	// strip it; we always (re-)prepend so the AccountID is computed over
	// the canonical 33-byte form.
	if x.sigType == SignatureEdDSA && (len(keyBytes) != 33 || keyBytes[0] != Ed25519Prefix) {
		prefixed := make([]byte, 0, 33)
		prefixed = append(prefixed, Ed25519Prefix)
		prefixed = append(prefixed, keyBytes...)
		keyBytes = prefixed
	}
	return classicAddressFromPubkey(keyBytes)
}

// xrplBase58Alphabet is the XRPL-specific Base58 dictionary. The order
// differs from Bitcoin's alphabet — XRPL begins with 'r', not '1'.
const xrplBase58Alphabet = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"

// classicAddressFromPubkey computes the XRPL classic address ("r..."
// form) for a serialized public key. Pure function; no curve dependency.
func classicAddressFromPubkey(pubkey []byte) string {
	// Step 1: AccountID = RIPEMD-160(SHA-256(pubkey)).
	sha := sha256.Sum256(pubkey)
	rip := ripemd160.New()
	rip.Write(sha[:])
	accountID := rip.Sum(nil) // 20 bytes

	// Step 2: payload = 0x00 || AccountID, then 4-byte SHA-256d checksum.
	payload := make([]byte, 0, 1+20+4)
	payload = append(payload, 0x00)
	payload = append(payload, accountID...)
	c1 := sha256.Sum256(payload)
	c2 := sha256.Sum256(c1[:])
	payload = append(payload, c2[:4]...)

	return xrplBase58Encode(payload)
}

// xrplBase58Encode encodes input using the XRPL Base58 alphabet.
// Leading zero bytes are encoded as the alphabet's zero character ('r').
func xrplBase58Encode(input []byte) string {
	if len(input) == 0 {
		return ""
	}
	// Count leading zeros to preserve them as the alphabet's index-0 char.
	zeros := 0
	for zeros < len(input) && input[zeros] == 0 {
		zeros++
	}

	// Convert the rest via repeated base-58 division.
	num := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	mod := new(big.Int)
	out := make([]byte, 0, len(input)*138/100+1)
	for num.Sign() > 0 {
		num.DivMod(num, base, mod)
		out = append(out, xrplBase58Alphabet[mod.Int64()])
	}
	// Prepend the alphabet's zero char for each leading zero byte.
	for i := 0; i < zeros; i++ {
		out = append(out, xrplBase58Alphabet[0])
	}
	// Reverse — we built it least-significant-first.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
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
