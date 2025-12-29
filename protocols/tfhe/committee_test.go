// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package tfhe

import (
	"context"
	"testing"
)

func makeKey(id uint32) KeyShare {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(id)*0x33 ^ byte(i)
	}
	return KeyShare{PartyID: id, Bytes: b}
}

func collect(t *testing.T, n uint32, sess [32]byte, ct FHECiphertext) ([]FHEThresholdShare, map[uint32]KeyShare) {
	t.Helper()
	pd := NewPartialDecrypter()
	keys := make(map[uint32]KeyShare, n)
	shares := make([]FHEThresholdShare, 0, n)
	for i := uint32(1); i <= n; i++ {
		k := makeKey(i)
		keys[i] = k
		s, err := pd.PartialDecrypt(context.Background(), k, ct, sess)
		if err != nil {
			t.Fatalf("partial decrypt %d: %v", i, err)
		}
		shares = append(shares, s)
	}
	return shares, keys
}

func TestCommittee_HappyPath_2of3(t *testing.T) {
	ct := NewFHECiphertext([]byte("verdict-allow"))
	var sess [32]byte
	copy(sess[:], "session-A")
	shares, keys := collect(t, 3, sess, ct)

	a := &ShareAggregator{PartyKeys: keys}
	res, plaintext, err := a.Aggregate(context.Background(), ct, shares[:2], 2, sess)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if res.Status != StatusOK {
		t.Fatalf("status = %s, want %s", res.Status, StatusOK)
	}
	if string(plaintext) != "verdict-allow" {
		t.Fatalf("plaintext = %q", plaintext)
	}
}

func TestCommittee_InsufficientQuorum(t *testing.T) {
	ct := NewFHECiphertext([]byte("v"))
	var sess [32]byte
	shares, keys := collect(t, 3, sess, ct)

	a := &ShareAggregator{PartyKeys: keys}
	res, _, err := a.Aggregate(context.Background(), ct, shares[:1], 2, sess)
	if err == nil {
		t.Fatal("expected ErrShareCount")
	}
	if res.Status != StatusInsufficientQuorum {
		t.Fatalf("status = %s, want insufficient_quorum", res.Status)
	}
}

func TestCommittee_TamperedMAC(t *testing.T) {
	ct := NewFHECiphertext([]byte("v"))
	var sess [32]byte
	shares, keys := collect(t, 3, sess, ct)

	// Flip a MAC byte on share 0.
	shares[0].MAC[0] ^= 0x01

	a := &ShareAggregator{PartyKeys: keys}
	res, _, err := a.Aggregate(context.Background(), ct, shares, 2, sess)
	if err == nil {
		t.Fatal("expected MAC failure")
	}
	if res.Status != StatusBadShare {
		t.Fatalf("status = %s, want bad_share", res.Status)
	}
}

func TestCommittee_WrongCiphertextRejected(t *testing.T) {
	ct1 := NewFHECiphertext([]byte("a"))
	ct2 := NewFHECiphertext([]byte("b"))
	var sess [32]byte
	shares, keys := collect(t, 3, sess, ct1)

	a := &ShareAggregator{PartyKeys: keys}
	res, _, err := a.Aggregate(context.Background(), ct2, shares, 2, sess)
	if err == nil {
		t.Fatal("expected ciphertext-mismatch failure")
	}
	if res.Status != StatusCiphertextMismatch {
		t.Fatalf("status = %s, want ciphertext_mismatch", res.Status)
	}
}

func TestCommittee_WrongSessionRejected(t *testing.T) {
	ct := NewFHECiphertext([]byte("v"))
	var sess1, sess2 [32]byte
	copy(sess1[:], "session-1")
	copy(sess2[:], "session-2")
	shares, keys := collect(t, 3, sess1, ct)

	a := &ShareAggregator{PartyKeys: keys}
	res, _, err := a.Aggregate(context.Background(), ct, shares, 2, sess2)
	if err == nil {
		t.Fatal("expected session-mismatch failure")
	}
	if res.Status != StatusBadShare {
		t.Fatalf("status = %s, want bad_share", res.Status)
	}
}

func TestCommittee_PublicKeyPath_NoMACVerify(t *testing.T) {
	// PartyKeys nil → MAC verification skipped (cross-committee bootstrap path).
	ct := NewFHECiphertext([]byte("v"))
	var sess [32]byte
	shares, _ := collect(t, 3, sess, ct)
	// Tamper one MAC; aggregator should still return OK because PartyKeys is nil.
	shares[0].MAC[0] ^= 0x01

	a := NewShareAggregator()
	res, _, err := a.Aggregate(context.Background(), ct, shares, 2, sess)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if res.Status != StatusOK {
		t.Fatalf("status = %s, want OK", res.Status)
	}
}

func TestCommittee_DuplicatePartyID(t *testing.T) {
	ct := NewFHECiphertext([]byte("v"))
	var sess [32]byte
	shares, keys := collect(t, 3, sess, ct)

	// Duplicate party 1 share; only first should count.
	dup := append([]FHEThresholdShare{}, shares[0], shares[0], shares[1])

	a := &ShareAggregator{PartyKeys: keys}
	res, _, err := a.Aggregate(context.Background(), ct, dup, 2, sess)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if res.ShareCount != 2 {
		t.Fatalf("ShareCount = %d, want 2", res.ShareCount)
	}
}

func TestNewFHECiphertext_DeterministicID(t *testing.T) {
	a := NewFHECiphertext([]byte("hello"))
	b := NewFHECiphertext([]byte("hello"))
	if a.ID != b.ID {
		t.Fatal("equal bytes must produce equal IDs")
	}
	c := NewFHECiphertext([]byte("hello!"))
	if a.ID == c.ID {
		t.Fatal("different bytes must produce different IDs")
	}
}
