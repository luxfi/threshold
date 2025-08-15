// Package adapters provides chain-specific implementations for threshold signatures
package adapters

import (
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
)

// SignatureType defines the signature algorithm
type SignatureType int

const (
	SignatureECDSA SignatureType = iota
	SignatureEdDSA
	SignatureSchnorr
	SignatureBLS
	SignatureRingtail // Post-quantum lattice-based
)

// Share represents a party's secret share
type Share struct {
	ID    party.ID
	Value curve.Scalar
	Index int
}

// PartialSig represents a partial signature from one party
type PartialSig interface {
	GetPartyID() party.ID
	Serialize() []byte
}

// FullSig represents a complete threshold signature
type FullSig interface {
	Verify(pubKey curve.Point, message []byte) bool
	Serialize() []byte
}

// SignerAdapter is the common interface for all chain-specific adapters
type SignerAdapter interface {
	// Digest computes chain-specific message digest
	Digest(tx interface{}) ([]byte, error)
	
	// SignEC creates a partial signature with a party's share
	SignEC(digest []byte, share Share) (PartialSig, error)
	
	// AggregateEC combines partial signatures into a full signature
	AggregateEC(parts []PartialSig) (FullSig, error)
	
	// Encode converts signature to chain-specific wire format
	Encode(full FullSig) ([]byte, error)
	
	// ValidateConfig checks if configuration is valid for this chain
	ValidateConfig(config *UnifiedConfig) error
}

// UnifiedConfig represents configuration for unified LSS
type UnifiedConfig struct {
	// Common fields
	ID         party.ID
	Threshold  int
	Generation uint64
	PartyIDs   []party.ID
	
	// Signature type
	SignatureScheme SignatureType
	
	// Curve-specific
	Group curve.Curve
	
	// Shared secrets (works for both EC and PQ)
	SecretShare interface{} // curve.Scalar for EC, lattice element for PQ
	PublicKey   interface{} // curve.Point for EC, lattice public key for PQ
	
	// Additional scheme-specific data
	ECDSAConfig    *ECDSAExtensions
	EdDSAConfig    *EdDSAExtensions
	RingtailConfig *RingtailExtensions
	
	// Verification shares for all parties
	VerificationShares map[party.ID]interface{}
}

// ECDSAExtensions holds ECDSA-specific configuration
type ECDSAExtensions struct {
	PaillierKey    interface{} // Paillier secret key
	PedersenParams interface{} // Pedersen parameters
	ChainCode      []byte      // HD wallet chain code
}

// EdDSAExtensions holds EdDSA-specific configuration
type EdDSAExtensions struct {
	AuxRand []byte // Auxiliary randomness for deterministic nonces
}

// RingtailExtensions holds Ringtail PQ-specific configuration
type RingtailExtensions struct {
	// Lattice parameters
	N         int     // Lattice dimension
	Q         int     // Modulus
	Sigma     float64 // Gaussian parameter
	SecurityLevel int // 128, 192, or 256 bits
	
	// Offline preprocessing store
	PreprocessingShares []RingtailPreprocessing
	
	// Public parameters
	PublicMatrix interface{} // A matrix for LWE
}

// RingtailPreprocessing represents offline preprocessing for Ringtail
type RingtailPreprocessing struct {
	ID        string
	Round1    interface{} // Offline round 1 data
	Round2    interface{} // Offline round 2 data
	Consumed  bool
}

// ECDSA signature components
type ECDSAPartialSig struct {
	PartyID party.ID
	R       curve.Scalar
	S       curve.Scalar
}

func (e *ECDSAPartialSig) GetPartyID() party.ID { return e.PartyID }
func (e *ECDSAPartialSig) Serialize() []byte {
	// Serialize R || S
	rBytes, _ := e.R.MarshalBinary()
	sBytes, _ := e.S.MarshalBinary()
	return append(rBytes, sBytes...)
}

type ECDSAFullSig struct {
	R curve.Scalar
	S curve.Scalar
}

func (e *ECDSAFullSig) Verify(pubKey curve.Point, message []byte) bool {
	// ECDSA verification logic
	return true // Placeholder
}

func (e *ECDSAFullSig) Serialize() []byte {
	rBytes, _ := e.R.MarshalBinary()
	sBytes, _ := e.S.MarshalBinary()
	return append(rBytes, sBytes...)
}

// EdDSA signature components
type EdDSAPartialSig struct {
	PartyID party.ID
	R       curve.Point
	Z       curve.Scalar
}

func (e *EdDSAPartialSig) GetPartyID() party.ID { return e.PartyID }
func (e *EdDSAPartialSig) Serialize() []byte {
	rBytes, _ := e.R.MarshalBinary()
	zBytes, _ := e.Z.MarshalBinary()
	return append(rBytes, zBytes...)
}

type EdDSAFullSig struct {
	R curve.Point
	Z curve.Scalar
}

func (e *EdDSAFullSig) Verify(pubKey curve.Point, message []byte) bool {
	// EdDSA verification logic
	return true // Placeholder
}

func (e *EdDSAFullSig) Serialize() []byte {
	rBytes, _ := e.R.MarshalBinary()
	zBytes, _ := e.Z.MarshalBinary()
	return append(rBytes, zBytes...)
}

// Ringtail PQ signature components
type RingtailPartialSig struct {
	PartyID party.ID
	Share   interface{} // Lattice element
}

func (r *RingtailPartialSig) GetPartyID() party.ID { return r.PartyID }
func (r *RingtailPartialSig) Serialize() []byte {
	// Serialize lattice element
	return []byte{} // Placeholder
}

type RingtailFullSig struct {
	Signature interface{} // Complete lattice signature
	Size      int         // Signature size in bytes
}

func (r *RingtailFullSig) Verify(pubKey curve.Point, message []byte) bool {
	// Ringtail verification logic
	return true // Placeholder
}

func (r *RingtailFullSig) Serialize() []byte {
	// ~13.4KB for 128-bit security as per Ringtail paper
	return make([]byte, r.Size)
}

// AdapterFactory creates appropriate adapter for a chain
type AdapterFactory struct{}

// NewAdapter creates a chain-specific adapter
func (f *AdapterFactory) NewAdapter(chain string, sigType SignatureType) SignerAdapter {
	switch chain {
	case "xrpl":
		return NewXRPLAdapter(sigType, false)
	case "ethereum":
		return NewEthereumAdapter()
	case "bitcoin":
		return NewBitcoinAdapter(sigType)
	case "solana":
		return NewSolanaAdapter()
	case "ton":
		return NewTONAdapter(0) // basechain by default
	case "cardano":
		return NewCardanoAdapter(sigType, 0x01, EraBabbage) // mainnet, current era
	case "cosmos":
		// TODO: Implement Cosmos adapter
		return nil
	case "polkadot":
		// TODO: Implement Polkadot adapter
		return nil
	default:
		return nil
	}
}

// GetSupportedChains returns list of supported blockchain networks
func GetSupportedChains() []string {
	return []string{
		"xrpl",
		"ethereum",
		"bitcoin",
		"solana",
		"cosmos",
		"polkadot",
		"avalanche",
		"binance",
		"cardano",
		"near",
		"aptos",
		"sui",
	}
}

// GetChainRequirements returns specific requirements for a chain
func GetChainRequirements(chain string) map[string]interface{} {
	requirements := map[string]map[string]interface{}{
		"xrpl": {
			"signature_types": []SignatureType{SignatureECDSA, SignatureEdDSA},
			"low_s_required":  true,
			"max_threshold":   8,
			"prefix_ed25519":  true,
		},
		"ethereum": {
			"signature_types": []SignatureType{SignatureECDSA},
			"low_s_required":  true,
			"eip155_chainid":  true,
			"typed_tx":        true,
		},
		"bitcoin": {
			"signature_types": []SignatureType{SignatureECDSA, SignatureSchnorr},
			"low_s_required":  true,
			"taproot_support": true,
			"sighash_types":   true,
		},
		"solana": {
			"signature_types": []SignatureType{SignatureEdDSA},
			"ed25519_only":    true,
			"program_verify":  true,
		},
		"polkadot": {
			"signature_types": []SignatureType{SignatureSchnorr},
			"sr25519_native":  true,
			"merlin_transcript": true,
		},
	}
	
	if req, exists := requirements[chain]; exists {
		return req
	}
	return nil
}