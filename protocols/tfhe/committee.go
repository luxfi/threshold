// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// What a committee member persists, and the one wire form of a ciphertext.

package tfhe

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/luxfi/fhe"
)

// maxBytes caps a ciphertext on the wire, bounding the allocation
// fhe.BitCiphertext.UnmarshalBinary makes from its own length prefixes.
const maxBytes = 32 << 20

// maxBits caps the declared bit width, matching the widest fhe.FheUintType.
const maxBits = 256

// digestTag domain-separates the ciphertext digest.
const digestTag = "LUX/THRESHOLD/TFHE/CIPHERTEXT/v1"

// Member is one committee member's persisted state: the collective public key
// everybody encrypts under, and this member's single share. Share is secret
// material; there is no field for a whole key, so a Member cannot decrypt on
// its own.
type Member struct {
	// Params is the FHE parameter set, so a stored Member is self-describing.
	Params fhe.ParametersLiteral `json:"params"`

	// Threshold is how many partial decryptions recover a plaintext.
	Threshold int `json:"threshold"`

	// Total is the committee size at generation time.
	Total int `json:"total"`

	// Key is the collective LWE public key, fhe.PublicKey.MarshalBinary.
	Key []byte `json:"key"`

	// Share is this member's Shamir share of the collective secret. Its Index
	// is the member's 1-based committee position.
	Share Share `json:"share"`
}

// Parameters resolves the stored literal into usable FHE parameters.
func (m *Member) Parameters() (fhe.Parameters, error) {
	return fhe.NewParametersFromLiteral(m.Params)
}

// Collective decodes the stored collective public key.
func (m *Member) Collective() (*fhe.PublicKey, error) {
	pk := new(fhe.PublicKey)
	if err := pk.UnmarshalBinary(m.Key); err != nil {
		return nil, fmt.Errorf("tfhe: collective public key: %w", err)
	}
	return pk, nil
}

// Validate rejects a stored Member whose share disagrees with its parameter
// set or committee size. It runs on every load.
func (m *Member) Validate() error {
	if m.Threshold < 1 || m.Threshold > m.Total {
		return fmt.Errorf("tfhe: threshold %d out of range for committee of %d", m.Threshold, m.Total)
	}
	if m.Share.Index < 1 || m.Share.Index > m.Total {
		return fmt.Errorf("tfhe: share index %d out of range [1,%d]", m.Share.Index, m.Total)
	}
	if m.Share.Total != m.Total {
		return fmt.Errorf("tfhe: share committee size %d disagrees with %d", m.Share.Total, m.Total)
	}
	params, err := m.Parameters()
	if err != nil {
		return fmt.Errorf("tfhe: parameters: %w", err)
	}
	if q := params.QLWE(); m.Share.Q != q {
		return fmt.Errorf("tfhe: share modulus %d disagrees with parameter set %d", m.Share.Q, q)
	}
	if n := params.ParamsLWE().RingQ().N(); len(m.Share.Coeffs) != n {
		return fmt.Errorf("tfhe: share length %d disagrees with ring degree %d", len(m.Share.Coeffs), n)
	}
	if len(m.Key) == 0 {
		return fmt.Errorf("tfhe: no collective public key")
	}
	return nil
}

// Marshal encodes a Member for a key store.
func Marshal(m *Member) ([]byte, error) { return json.Marshal(m) }

// Unmarshal decodes and validates a stored Member.
func Unmarshal(b []byte) (*Member, error) {
	m := new(Member)
	if err := json.Unmarshal(b, m); err != nil {
		return nil, fmt.Errorf("tfhe: decode member: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return m, nil
}

// Encrypt encrypts value under the collective public key and returns the wire
// form. No secret key is involved.
func Encrypt(params fhe.Parameters, pub *fhe.PublicKey, value uint64, t fhe.FheUintType) ([]byte, error) {
	if pub == nil || pub.PKLWE == nil {
		return nil, fmt.Errorf("tfhe: nil collective public key")
	}
	ct, err := fhe.NewBitwisePublicEncryptor(params, pub).EncryptUint64(value, t)
	if err != nil {
		return nil, fmt.Errorf("tfhe: encrypt: %w", err)
	}
	return ct.MarshalBinary()
}

// Parse decodes a ciphertext, bounding input size and declared width
// before allocating from either.
func Parse(b []byte) (*fhe.BitCiphertext, error) {
	if len(b) < 5 {
		return nil, fmt.Errorf("tfhe: ciphertext is %d bytes", len(b))
	}
	if len(b) > maxBytes {
		return nil, fmt.Errorf("tfhe: ciphertext %d bytes exceeds %d", len(b), maxBytes)
	}
	// The declared width is checked before decoding, because
	// fhe.BitCiphertext.UnmarshalBinary allocates from it.
	if n := binary.LittleEndian.Uint32(b); n < 1 || n > maxBits {
		return nil, fmt.Errorf("tfhe: ciphertext declares %d bits, want [1,%d]", n, maxBits)
	}
	ct := new(fhe.BitCiphertext)
	if err := ct.UnmarshalBinary(b); err != nil {
		return nil, fmt.Errorf("tfhe: decode ciphertext: %w", err)
	}
	n := ct.NumBits()
	if got := len(ct.Bits()); got != n {
		return nil, fmt.Errorf("tfhe: ciphertext declares %d bits but carries %d", n, got)
	}
	for i, bit := range ct.Bits() {
		if bit == nil || bit.Ciphertext == nil || len(bit.Value) < 2 {
			return nil, fmt.Errorf("tfhe: ciphertext bit %d is malformed", i)
		}
	}
	return ct, nil
}

// Digest binds a partial decryption to the ciphertext bytes it was computed
// over. Taken over the wire form, so it is canonical by construction.
func Digest(ciphertext []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(digestTag))
	h.Write(ciphertext)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Value assembles plaintext bits, least significant first, into an integer.
// Bits beyond 64 are ignored.
func Value(bits []bool) uint64 {
	var v uint64
	for i, b := range bits {
		if i >= 64 {
			break
		}
		if b {
			v |= 1 << uint(i)
		}
	}
	return v
}
