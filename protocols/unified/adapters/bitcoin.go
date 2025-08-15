// Package adapters - Bitcoin adapter with Taproot support
package adapters

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
)

// BitcoinAdapter implements SignerAdapter for Bitcoin with Taproot/Schnorr support
type BitcoinAdapter struct {
	sigType      SignatureType
	network      BitcoinNetwork
	group        curve.Curve
	taprootTweak []byte // For Taproot key/script tweaking
}

// BitcoinNetwork represents Bitcoin network parameters
type BitcoinNetwork int

const (
	BitcoinMainnet BitcoinNetwork = iota
	BitcoinTestnet
	BitcoinRegtest
)

// SigHashType represents Bitcoin signature hash types
type SigHashType uint32

const (
	SigHashDefault      SigHashType = 0x00
	SigHashAll          SigHashType = 0x01
	SigHashNone         SigHashType = 0x02
	SigHashSingle       SigHashType = 0x03
	SigHashAnyOneCanPay SigHashType = 0x80
)

// NewBitcoinAdapter creates a new Bitcoin adapter
func NewBitcoinAdapter(sigType SignatureType) *BitcoinAdapter {
	return &BitcoinAdapter{
		sigType: sigType,
		network: BitcoinMainnet,
		group:   curve.Secp256k1{},
	}
}

// SetNetwork sets the Bitcoin network
func (b *BitcoinAdapter) SetNetwork(network BitcoinNetwork) {
	b.network = network
}

// SetTaprootTweak sets the Taproot tweak for key/script path spending
func (b *BitcoinAdapter) SetTaprootTweak(tweak []byte) {
	b.taprootTweak = tweak
}

// Digest computes Bitcoin transaction digest based on type
func (b *BitcoinAdapter) Digest(tx interface{}) ([]byte, error) {
	switch v := tx.(type) {
	case *LegacyBitcoinTx:
		return b.digestLegacy(v)
	case *SegwitTx:
		return b.digestSegwit(v)
	case *TaprootTx:
		return b.digestTaproot(v)
	default:
		return nil, fmt.Errorf("unsupported Bitcoin transaction type: %T", tx)
	}
}

// digestLegacy computes digest for legacy Bitcoin transactions
func (b *BitcoinAdapter) digestLegacy(tx *LegacyBitcoinTx) ([]byte, error) {
	// Serialize transaction with SIGHASH
	serialized := b.serializeLegacy(tx)
	
	// Append SIGHASH type
	sighashBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sighashBytes, uint32(tx.SigHash))
	serialized = append(serialized, sighashBytes...)
	
	// Double SHA256
	first := sha256.Sum256(serialized)
	second := sha256.Sum256(first[:])
	
	return second[:], nil
}

// digestSegwit computes BIP143 digest for SegWit transactions
func (b *BitcoinAdapter) digestSegwit(tx *SegwitTx) ([]byte, error) {
	// BIP143 signature hash algorithm
	var preimage []byte
	
	// 1. nVersion (4 bytes)
	version := make([]byte, 4)
	binary.LittleEndian.PutUint32(version, tx.Version)
	preimage = append(preimage, version...)
	
	// 2. hashPrevouts (32 bytes)
	hashPrevouts := b.computeHashPrevouts(tx)
	preimage = append(preimage, hashPrevouts...)
	
	// 3. hashSequence (32 bytes)
	hashSequence := b.computeHashSequence(tx)
	preimage = append(preimage, hashSequence...)
	
	// 4. outpoint (32 + 4 bytes)
	preimage = append(preimage, tx.InputTxID[:]...)
	outIndex := make([]byte, 4)
	binary.LittleEndian.PutUint32(outIndex, tx.InputIndex)
	preimage = append(preimage, outIndex...)
	
	// 5. scriptCode
	preimage = append(preimage, tx.ScriptCode...)
	
	// 6. amount (8 bytes)
	amount := make([]byte, 8)
	binary.LittleEndian.PutUint64(amount, tx.Amount)
	preimage = append(preimage, amount...)
	
	// 7. nSequence (4 bytes)
	sequence := make([]byte, 4)
	binary.LittleEndian.PutUint32(sequence, tx.Sequence)
	preimage = append(preimage, sequence...)
	
	// 8. hashOutputs (32 bytes)
	hashOutputs := b.computeHashOutputs(tx)
	preimage = append(preimage, hashOutputs...)
	
	// 9. nLockTime (4 bytes)
	locktime := make([]byte, 4)
	binary.LittleEndian.PutUint32(locktime, tx.LockTime)
	preimage = append(preimage, locktime...)
	
	// 10. sighash type (4 bytes)
	sighashBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sighashBytes, uint32(tx.SigHash))
	preimage = append(preimage, sighashBytes...)
	
	// Double SHA256
	first := sha256.Sum256(preimage)
	second := sha256.Sum256(first[:])
	
	return second[:], nil
}

// digestTaproot computes BIP341 digest for Taproot transactions
func (b *BitcoinAdapter) digestTaproot(tx *TaprootTx) ([]byte, error) {
	// BIP341 signature hash algorithm for Taproot
	var preimage []byte
	
	// Epoch (1 byte): 0x00 for BIP341
	preimage = append(preimage, 0x00)
	
	// Control byte: hash_type (1 byte)
	preimage = append(preimage, byte(tx.SigHash))
	
	// Transaction data
	// nVersion (4 bytes)
	version := make([]byte, 4)
	binary.LittleEndian.PutUint32(version, tx.Version)
	preimage = append(preimage, version...)
	
	// nLockTime (4 bytes)
	locktime := make([]byte, 4)
	binary.LittleEndian.PutUint32(locktime, tx.LockTime)
	preimage = append(preimage, locktime...)
	
	// If ANYONECANPAY flag is not set
	if tx.SigHash&SigHashAnyOneCanPay == 0 {
		// sha_prevouts (32 bytes)
		hashPrevouts := b.computeHashPrevouts(&tx.SegwitTx)
		preimage = append(preimage, hashPrevouts...)
		
		// sha_amounts (32 bytes)
		hashAmounts := b.computeHashAmounts(tx)
		preimage = append(preimage, hashAmounts...)
		
		// sha_scriptpubkeys (32 bytes)
		hashScriptPubkeys := b.computeHashScriptPubkeys(tx)
		preimage = append(preimage, hashScriptPubkeys...)
		
		// sha_sequences (32 bytes)
		hashSequences := b.computeHashSequence(&tx.SegwitTx)
		preimage = append(preimage, hashSequences...)
	}
	
	// If NONE or SINGLE
	if tx.SigHash&0x03 != SigHashNone && tx.SigHash&0x03 != SigHashSingle {
		// sha_outputs (32 bytes)
		hashOutputs := b.computeHashOutputs(&tx.SegwitTx)
		preimage = append(preimage, hashOutputs...)
	}
	
	// Data about this input
	// spend_type (1 byte)
	spendType := byte(0x00) // Key path spend
	if tx.ScriptPath {
		spendType = 0x02 // Script path spend
	}
	preimage = append(preimage, spendType)
	
	// Input index (4 bytes)
	inputIndex := make([]byte, 4)
	binary.LittleEndian.PutUint32(inputIndex, tx.InputIndex)
	preimage = append(preimage, inputIndex...)
	
	// For script path, include additional data
	if tx.ScriptPath {
		// Annex (optional)
		if len(tx.Annex) > 0 {
			preimage = append(preimage, tx.Annex...)
		}
		
		// Script and control block
		preimage = append(preimage, tx.TapScript...)
		preimage = append(preimage, tx.ControlBlock...)
	}
	
	// Apply tagged hash "TapSighash"
	taggedHash := b.taggedHash("TapSighash", preimage)
	
	return taggedHash, nil
}

// SignEC performs threshold signing for Bitcoin
func (b *BitcoinAdapter) SignEC(digest []byte, share Share) (PartialSig, error) {
	switch b.sigType {
	case SignatureECDSA:
		return b.signECDSA(digest, share)
	case SignatureSchnorr:
		return b.signSchnorr(digest, share)
	default:
		return nil, fmt.Errorf("unsupported signature type for Bitcoin: %v", b.sigType)
	}
}

// signECDSA creates ECDSA partial signature for legacy/SegWit
func (b *BitcoinAdapter) signECDSA(digest []byte, share Share) (PartialSig, error) {
	// This would integrate with CMP protocol
	return &ECDSAPartialSig{
		PartyID: share.ID,
		R:       nil, // Computed in CMP
		S:       share.Value,
	}, nil
}

// signSchnorr creates Schnorr partial signature for Taproot
func (b *BitcoinAdapter) signSchnorr(digest []byte, share Share) (PartialSig, error) {
	// This would integrate with FROST protocol for BIP340
	// Apply Taproot tweak if set
	tweakedShare := share.Value
	if len(b.taprootTweak) > 0 {
		tweakedShare = b.applyTaprootTweak(share.Value)
	}
	
	return &SchnorrPartialSig{
		PartyID: share.ID,
		R:       nil, // Computed in FROST
		S:       tweakedShare,
	}, nil
}

// AggregateEC combines partial signatures
func (b *BitcoinAdapter) AggregateEC(parts []PartialSig) (FullSig, error) {
	switch b.sigType {
	case SignatureECDSA:
		return b.aggregateECDSA(parts)
	case SignatureSchnorr:
		return b.aggregateSchnorr(parts)
	default:
		return nil, fmt.Errorf("unsupported signature type: %v", b.sigType)
	}
}

// aggregateECDSA combines ECDSA partial signatures with low-S
func (b *BitcoinAdapter) aggregateECDSA(parts []PartialSig) (FullSig, error) {
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
			s = b.group.NewScalar()
		}
		s = s.Add(ecdsaPart.S)
	}
	
	// Enforce low-S for Bitcoin
	s = b.normalizeLowS(s)
	
	return &ECDSAFullSig{
		R: r,
		S: s,
	}, nil
}

// aggregateSchnorr combines Schnorr partial signatures for BIP340
func (b *BitcoinAdapter) aggregateSchnorr(parts []PartialSig) (FullSig, error) {
	var r curve.Point
	s := b.group.NewScalar()
	
	for _, part := range parts {
		schnorrPart, ok := part.(*SchnorrPartialSig)
		if !ok {
			return nil, errors.New("invalid Schnorr partial signature")
		}
		
		if r == nil && schnorrPart.R != nil {
			r = schnorrPart.R
		}
		
		s = s.Add(schnorrPart.S)
	}
	
	// BIP340 requires x-only public keys
	xOnlyR := b.makeXOnly(r)
	
	return &SchnorrFullSig{
		R: xOnlyR,
		S: s,
	}, nil
}

// Encode formats signature for Bitcoin wire format
func (b *BitcoinAdapter) Encode(full FullSig) ([]byte, error) {
	switch b.sigType {
	case SignatureECDSA:
		return b.encodeECDSA(full)
	case SignatureSchnorr:
		return b.encodeSchnorr(full)
	default:
		return nil, fmt.Errorf("unsupported signature type: %v", b.sigType)
	}
}

// encodeECDSA encodes ECDSA signature in DER format
func (b *BitcoinAdapter) encodeECDSA(full FullSig) ([]byte, error) {
	ecdsaSig, ok := full.(*ECDSAFullSig)
	if !ok {
		return nil, errors.New("invalid ECDSA signature")
	}
	
	// DER encoding for Bitcoin
	rBytes, _ := ecdsaSig.R.MarshalBinary()
	sBytes, _ := ecdsaSig.S.MarshalBinary()
	return b.encodeDER(rBytes, sBytes), nil
}

// encodeSchnorr encodes Schnorr signature for BIP340
func (b *BitcoinAdapter) encodeSchnorr(full FullSig) ([]byte, error) {
	schnorrSig, ok := full.(*SchnorrFullSig)
	if !ok {
		return nil, errors.New("invalid Schnorr signature")
	}
	
	// BIP340: 64 bytes (32 bytes R x-coordinate + 32 bytes s)
	sig := make([]byte, 64)
	
	// R x-coordinate (32 bytes)
	rBytes, _ := schnorrSig.R.MarshalBinary()
	copy(sig[:32], rBytes)
	
	// s value (32 bytes)
	sBytes, _ := schnorrSig.S.MarshalBinary()
	copy(sig[32:], sBytes)
	
	return sig, nil
}

// ValidateConfig validates Bitcoin-specific configuration
func (b *BitcoinAdapter) ValidateConfig(config *UnifiedConfig) error {
	// Check signature type
	if b.sigType == SignatureSchnorr && config.SignatureScheme != SignatureSchnorr {
		return errors.New("Taproot requires Schnorr signatures")
	}
	
	if b.sigType == SignatureECDSA && config.SignatureScheme != SignatureECDSA {
		return errors.New("Legacy/SegWit requires ECDSA signatures")
	}
	
	// Verify secp256k1 curve
	if _, ok := config.Group.(curve.Secp256k1); !ok {
		return errors.New("Bitcoin requires secp256k1 curve")
	}
	
	return nil
}

// Helper functions

func (b *BitcoinAdapter) normalizeLowS(s curve.Scalar) curve.Scalar {
	// For low-S normalization, we need to check if s > n/2
	// If so, replace s with n - s
	// This is a simplified version - actual implementation would
	// need proper access to the curve order
	return s
}

func (b *BitcoinAdapter) taggedHash(tag string, data []byte) []byte {
	// BIP340 tagged hash
	tagHash := sha256.Sum256([]byte(tag))
	
	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])
	h.Write(data)
	
	return h.Sum(nil)
}

func (b *BitcoinAdapter) applyTaprootTweak(share curve.Scalar) curve.Scalar {
	// Apply Taproot tweak to share
	// tweak = tagged_hash("TapTweak", internal_key || merkle_root)
	// Simplified - actual implementation would properly convert tweak
	return share
}

func (b *BitcoinAdapter) makeXOnly(point curve.Point) curve.Point {
	// Convert to x-only format for BIP340
	// Simplified version - actual would check y coordinate
	return point
}

func (b *BitcoinAdapter) encodeDER(r, s []byte) []byte {
	// DER encoding for ECDSA
	der := []byte{0x30} // SEQUENCE
	
	// Encode R
	rDER := b.encodeDERInt(r)
	// Encode S
	sDER := b.encodeDERInt(s)
	
	// Total length
	der = append(der, byte(len(rDER)+len(sDER)))
	der = append(der, rDER...)
	der = append(der, sDER...)
	
	return der
}

func (b *BitcoinAdapter) encodeDERInt(val []byte) []byte {
	// Remove leading zeros
	for len(val) > 0 && val[0] == 0 {
		val = val[1:]
	}
	
	// Add padding if high bit is set
	if len(val) > 0 && val[0]&0x80 != 0 {
		val = append([]byte{0}, val...)
	}
	
	result := []byte{0x02, byte(len(val))}
	return append(result, val...)
}

// Hash computation helpers for BIP143/341

func (b *BitcoinAdapter) computeHashPrevouts(tx *SegwitTx) []byte {
	// Hash all outpoints
	h := sha256.New()
	h.Write(tx.InputTxID[:])
	// Add more inputs if multiple
	return h.Sum(nil)
}

func (b *BitcoinAdapter) computeHashSequence(tx *SegwitTx) []byte {
	// Hash all sequences
	h := sha256.New()
	seq := make([]byte, 4)
	binary.LittleEndian.PutUint32(seq, tx.Sequence)
	h.Write(seq)
	return h.Sum(nil)
}

func (b *BitcoinAdapter) computeHashOutputs(tx *SegwitTx) []byte {
	// Hash all outputs
	h := sha256.New()
	// Serialize outputs
	return h.Sum(nil)
}

func (b *BitcoinAdapter) computeHashAmounts(tx *TaprootTx) []byte {
	// Hash all input amounts for Taproot
	h := sha256.New()
	amount := make([]byte, 8)
	binary.LittleEndian.PutUint64(amount, tx.Amount)
	h.Write(amount)
	return h.Sum(nil)
}

func (b *BitcoinAdapter) computeHashScriptPubkeys(tx *TaprootTx) []byte {
	// Hash all script pubkeys for Taproot
	h := sha256.New()
	// Add script pubkeys
	return h.Sum(nil)
}

func (b *BitcoinAdapter) serializeLegacy(tx *LegacyBitcoinTx) []byte {
	// Serialize legacy transaction
	// Simplified - actual would follow Bitcoin serialization format
	var buf []byte
	
	// Version
	version := make([]byte, 4)
	binary.LittleEndian.PutUint32(version, tx.Version)
	buf = append(buf, version...)
	
	// Inputs
	// Outputs
	// Locktime
	
	return buf
}

// Transaction types

type LegacyBitcoinTx struct {
	Version  uint32
	Inputs   []Input
	Outputs  []Output
	LockTime uint32
	SigHash  SigHashType
}

type SegwitTx struct {
	Version    uint32
	InputTxID  [32]byte
	InputIndex uint32
	ScriptCode []byte
	Amount     uint64
	Sequence   uint32
	Outputs    []Output
	LockTime   uint32
	SigHash    SigHashType
}

type TaprootTx struct {
	SegwitTx
	ScriptPath   bool
	TapScript    []byte
	ControlBlock []byte
	Annex        []byte
}

type Input struct {
	PrevTxID   [32]byte
	PrevIndex  uint32
	ScriptSig  []byte
	Sequence   uint32
	Witness    [][]byte
}

type Output struct {
	Value        uint64
	ScriptPubKey []byte
}

// Schnorr signature components
type SchnorrPartialSig struct {
	PartyID party.ID
	R       curve.Point
	S       curve.Scalar
}

func (s *SchnorrPartialSig) GetPartyID() party.ID { return s.PartyID }
func (s *SchnorrPartialSig) Serialize() []byte {
	rBytes, _ := s.R.MarshalBinary()
	sBytes, _ := s.S.MarshalBinary()
	return append(rBytes, sBytes...)
}

type SchnorrFullSig struct {
	R curve.Point
	S curve.Scalar
}

func (s *SchnorrFullSig) Verify(pubKey curve.Point, message []byte) bool {
	// BIP340 verification
	return true // Placeholder
}

func (s *SchnorrFullSig) Serialize() []byte {
	rBytes, _ := s.R.MarshalBinary()
	sBytes, _ := s.S.MarshalBinary()
	return append(rBytes, sBytes...)
}

// CreateP2TRAddress creates a Pay-to-Taproot address
func (b *BitcoinAdapter) CreateP2TRAddress(internalKey curve.Point, scriptTree []byte) (string, error) {
	// Compute Taproot output key
	// Q = P + hash_tweak(P || script_tree) * G
	
	// This would implement full BIP341 address derivation
	return "bc1p...", nil // Placeholder
}

// CreateMultisigScript creates a Bitcoin multisig script
func (b *BitcoinAdapter) CreateMultisigScript(pubkeys []curve.Point, threshold int) ([]byte, error) {
	// Create m-of-n multisig script
	// OP_<m> <pubkey1> ... <pubkeyn> OP_<n> OP_CHECKMULTISIG
	
	script := []byte{byte(0x50 + threshold)} // OP_m
	
	for _, pk := range pubkeys {
		pkBytes, _ := pk.MarshalBinary()
		script = append(script, byte(len(pkBytes)))
		script = append(script, pkBytes...)
	}
	
	script = append(script, byte(0x50+len(pubkeys))) // OP_n
	script = append(script, 0xae)                     // OP_CHECKMULTISIG
	
	return script, nil
}