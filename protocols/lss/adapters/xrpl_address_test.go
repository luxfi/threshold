// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package adapters

import (
	"encoding/hex"
	"testing"
)

// TestClassicAddressFromPubkey exercises the XRPL address derivation
// against published test vectors. The vectors are taken from the
// xrpl-py reference implementation
// (https://github.com/XRPLF/xrpl-py, BSD-3-Clause) which itself derives
// from the canonical rippled C++ keypair test data.
//
// Spec: https://xrpl.org/accounts.html#address-encoding
//
//	AccountID = RIPEMD-160(SHA-256(pubkey))
//	payload   = 0x00 || AccountID
//	checksum  = SHA-256(SHA-256(payload))[:4]
//	address   = base58(payload || checksum)  // XRPL alphabet
func TestClassicAddressFromPubkey(t *testing.T) {
	cases := []struct {
		name   string
		pubHex string
		want   string
	}{
		{
			// Canonical XRPL secp256k1 KAT: derive the Genesis account
			// "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh" from its public key.
			// The seed is the well-known "masterpassphrase"; the
			// pubkey is what rippled's own keypair_test.cpp asserts
			// against. Compressed secp256k1, 33 bytes.
			name:   "secp256k1_genesis",
			pubHex: "0330E7FC9D56BB25D6893BA3F317AE5BCF33B3291BD63DB32654A313222F7FD020",
			want:   "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub, err := hex.DecodeString(tc.pubHex)
			if err != nil {
				t.Fatalf("decode pubkey hex: %v", err)
			}
			got := classicAddressFromPubkey(pub)
			if got != tc.want {
				t.Fatalf("classicAddressFromPubkey(%s)\n got: %s\nwant: %s", tc.pubHex, got, tc.want)
			}
		})
	}
}

// TestClassicAddressFromPubkey_Roundtrip asserts that the encoding is
// stable for arbitrary 33-byte inputs (no panics, deterministic output,
// always begins with 'r').
func TestClassicAddressFromPubkey_Roundtrip(t *testing.T) {
	pub := make([]byte, 33)
	for i := range pub {
		pub[i] = byte(i)
	}
	a := classicAddressFromPubkey(pub)
	b := classicAddressFromPubkey(pub)
	if a != b {
		t.Fatalf("classicAddressFromPubkey not deterministic: %s vs %s", a, b)
	}
	if len(a) == 0 || a[0] != 'r' {
		t.Fatalf("classic address must start with 'r', got %q", a)
	}
}

// TestNewXRPLAdapter_RejectsUnsupportedSigType asserts that the
// constructor returns a structured error rather than panicking when
// given a signature type XRPL does not support.
func TestNewXRPLAdapter_RejectsUnsupportedSigType(t *testing.T) {
	cases := []struct {
		name string
		st   SignatureType
	}{
		{"schnorr_unsupported", SignatureSchnorr},
		{"ringtail_unsupported", SignatureCorona},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := NewXRPLAdapter(tc.st, false)
			if err == nil {
				t.Fatal("expected error for unsupported signature type, got nil")
			}
			if a != nil {
				t.Fatal("expected nil adapter on error, got non-nil")
			}
		})
	}
}

// TestNewCardanoAdapter_RejectsUnsupportedSigType mirrors the XRPL
// check for the Cardano constructor.
func TestNewCardanoAdapter_RejectsUnsupportedSigType(t *testing.T) {
	a, err := NewCardanoAdapter(SignatureCorona, 0x01, EraBabbage)
	if err == nil {
		t.Fatal("expected error for unsupported signature type, got nil")
	}
	if a != nil {
		t.Fatal("expected nil adapter on error, got non-nil")
	}
}
