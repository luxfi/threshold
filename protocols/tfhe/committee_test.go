// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package tfhe

import (
	"bytes"
	"context"
	"testing"

	"github.com/luxfi/fhe"
	"github.com/luxfi/threshold/pkg/party"
)

func makeWireKey(id uint32) KeyShare {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(id)*0x33 ^ byte(i)
	}
	return KeyShare{PartyID: id, Bytes: b}
}

// envelopeShares produces n shares that follow the FChain envelope
// path (no lattice work, just the MAC binding). Used to test the
// wire-authentication layer in isolation from threshold decryption.
func envelopeShares(t *testing.T, n uint32, sess [32]byte, ct FHECiphertext) ([]FHEThresholdShare, map[uint32]KeyShare) {
	t.Helper()
	keys := make(map[uint32]KeyShare, n)
	shares := make([]FHEThresholdShare, 0, n)
	for i := uint32(1); i <= n; i++ {
		k := makeWireKey(i)
		keys[i] = k
		shares = append(shares, PartialDecryptEnvelopeOnly(k, ct, sess))
	}
	return shares, keys
}

func TestCommittee_HappyPath_2of3(t *testing.T) {
	ct := NewFHECiphertext([]byte("verdict-allow"))
	var sess [32]byte
	copy(sess[:], "session-A")
	shares, keys := envelopeShares(t, 3, sess, ct)

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
	shares, keys := envelopeShares(t, 3, sess, ct)

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
	shares, keys := envelopeShares(t, 3, sess, ct)

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
	shares, keys := envelopeShares(t, 3, sess, ct1)

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
	shares, keys := envelopeShares(t, 3, sess1, ct)

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
	shares, _ := envelopeShares(t, 3, sess, ct)
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
	shares, keys := envelopeShares(t, 3, sess, ct)

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

// latticeFixture builds a real threshold-FHE setup, encrypts a single
// bit, and returns:
//   - the BitCiphertext bytes (envelope payload)
//   - the per-party (SecretKeyShare, KeyShare) pairs
//   - the Protocol used for combine
//   - the FHE params
func latticeFixture(t *testing.T, value bool, threshold, total int) (
	ct *fhe.BitCiphertext,
	envBytes []byte,
	keyShares map[uint32]KeyShare,
	secretShares map[uint32]*SecretKeyShare,
	combiner *Protocol,
	params fhe.Parameters,
) {
	t.Helper()
	p, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	params = p
	parties := makeParties(total)
	kg, _ := NewKeyGenerator(threshold, total, params, nil)
	masterSK, pubKey, shares, err := kg.GenerateKeysWithMaster(context.Background(), parties)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	enc := fhe.NewEncryptor(params, masterSK)
	bit := enc.Encrypt(value)
	ct = fhe.WrapBoolCiphertext(bit)
	envBytes, err = ct.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	keyShares = make(map[uint32]KeyShare, total)
	secretShares = make(map[uint32]*SecretKeyShare, total)
	for i, pid := range parties {
		id := uint32(i + 1)
		keyShares[id] = makeWireKey(id)
		secretShares[id] = shares[pid]
	}

	combinerCfg := &Config{
		Threshold:      threshold,
		TotalParties:   total,
		PartyID:        parties[0],
		Generation:     1,
		FHEParams:      params,
		PublicKey:      pubKey,
		SecretKeyShare: shares[parties[0]],
	}
	combiner, err = NewProtocol(combinerCfg, nil)
	if err != nil {
		t.Fatalf("combiner: %v", err)
	}
	return
}

// TestCommittee_LatticePath_RoundTrip validates that the aggregator's
// lattice dispatch path recovers the plaintext bit when a real
// Protocol is wired in. Two parties contribute partials, aggregator
// authenticates them, decodes, and combines via Protocol.CombineShares.
func TestCommittee_LatticePath_RoundTrip(t *testing.T) {
	for _, value := range []bool{false, true} {
		ct, envBytes, keys, secrets, combiner, params := latticeFixture(t, value, 2, 3)
		ctEnv := NewFHECiphertext(envBytes)
		var sess [32]byte
		copy(sess[:], "lattice-dispatch")

		// Each party builds a wire share via PartialDecrypter, which
		// wraps the lattice partial-decrypt with the wire-layer MAC.
		var wireShares []FHEThresholdShare
		for id := uint32(1); id <= 2; id++ {
			pd := NewPartialDecrypter(secrets[id], params, 2)
			s, err := pd.PartialDecrypt(context.Background(), keys[id], ctEnv, sess)
			if err != nil {
				t.Fatalf("partial decrypt party %d: %v", id, err)
			}
			// IMPORTANT: the share's PartyID must equal the
			// SecretKeyShare's lattice Shamir index, since the
			// aggregator uses PartyID as the lattice combine
			// coordinate. We arranged the fixture so they line up
			// (party uint32 id == secret share Index).
			s.PartyID = uint32(secrets[id].Index)
			s.MAC = computeMAC(keys[id], s.PartyID, s.SessionID, s.CiphertextID, s.Partial)
			wireShares = append(wireShares, s)
		}

		// Build keys keyed by lattice index, matching the rebound shares.
		keysByIndex := make(map[uint32]KeyShare, 2)
		for id := uint32(1); id <= 2; id++ {
			keysByIndex[uint32(secrets[id].Index)] = keys[id]
		}

		a := &ShareAggregator{PartyKeys: keysByIndex, Protocol: combiner}
		res, plaintext, err := a.Aggregate(context.Background(), ctEnv, wireShares, 2, sess)
		if err != nil {
			t.Fatalf("aggregate: %v", err)
		}
		if res.Status != StatusOK {
			t.Fatalf("status = %s", res.Status)
		}
		// CombineShares returns one byte per packed bit. For a single-
		// bit ciphertext, the result is 1 byte; bit 0 = decoded value.
		want := byte(0)
		if value {
			want = 1
		}
		if len(plaintext) == 0 {
			t.Fatalf("empty plaintext")
		}
		if (plaintext[0] & 1) != want {
			t.Fatalf("decoded bit = %d, want %d", plaintext[0]&1, want)
		}
		_ = ct
	}
}

// TestCommittee_EnvelopePath confirms that with no Protocol wired the
// aggregator returns the verdict envelope unchanged.
func TestCommittee_EnvelopePath(t *testing.T) {
	ct := NewFHECiphertext([]byte("verdict-allow"))
	var sess [32]byte
	copy(sess[:], "envelope")
	shares, keys := envelopeShares(t, 3, sess, ct)

	a := &ShareAggregator{PartyKeys: keys}
	res, plaintext, err := a.Aggregate(context.Background(), ct, shares[:2], 2, sess)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if res.Status != StatusOK {
		t.Fatalf("status = %s", res.Status)
	}
	if !bytes.Equal(plaintext, ct.Bytes) {
		t.Fatalf("envelope plaintext mismatch: got %x, want %x", plaintext, ct.Bytes)
	}
}

// TestPartialDecrypter_RequiresShare guards against nil-share misuse.
func TestPartialDecrypter_RequiresShare(t *testing.T) {
	ct := NewFHECiphertext([]byte("x"))
	var sess [32]byte
	pd := NewPartialDecrypter(nil, fhe.Parameters{}, 2)
	if _, err := pd.PartialDecrypt(context.Background(), makeWireKey(1), ct, sess); err == nil {
		t.Fatal("expected error for nil SecretShare")
	}
}

// TestPartialDecrypter_UnmarshalFailureReportedCleanly confirms that an
// invalid envelope bytes blob produces a clear error rather than a panic.
func TestPartialDecrypter_UnmarshalFailureReportedCleanly(t *testing.T) {
	ct := NewFHECiphertext([]byte("not a ciphertext"))
	var sess [32]byte
	dummyShare := &SecretKeyShare{PartyID: party.ID("p1"), Index: 1}
	pd := NewPartialDecrypter(dummyShare, fhe.Parameters{}, 2)
	if _, err := pd.PartialDecrypt(context.Background(), makeWireKey(1), ct, sess); err == nil {
		t.Fatal("expected unmarshal error")
	}
}
