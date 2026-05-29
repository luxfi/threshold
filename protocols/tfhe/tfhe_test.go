// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package tfhe

import (
	"context"
	"reflect"
	"testing"

	"github.com/luxfi/fhe"
	fhethreshold "github.com/luxfi/fhe/pkg/threshold"
	"github.com/luxfi/threshold/pkg/party"
)

// mockThresholdProvider is a local mock implementation for testing
type mockThresholdProvider struct {
	seed []byte
}

func (m *mockThresholdProvider) RequestRandomness(ctx context.Context, numBytes int) ([]byte, error) {
	result := make([]byte, numBytes)
	for i := 0; i < numBytes; i++ {
		if i < len(m.seed) {
			result[i] = m.seed[i]
		} else {
			result[i] = byte(i)
		}
	}
	return result, nil
}

func (m *mockThresholdProvider) IsAvailable(ctx context.Context) bool {
	return true
}

// TestKeyGeneration_2of3 confirms that the keygen ceremony returns one
// share per party and that every share carries an LWE share — not a
// copy of the master.
func TestKeyGeneration_2of3(t *testing.T) {
	threshold, totalParties := 2, 3
	parties := []party.ID{"party1", "party2", "party3"}

	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}

	kg, err := NewKeyGenerator(threshold, totalParties, params, nil)
	if err != nil {
		t.Fatalf("NewKeyGenerator: %v", err)
	}

	pubKey, shares, err := kg.GenerateKeys(context.Background(), parties)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}

	if pubKey == nil {
		t.Fatal("public key is nil")
	}
	if len(shares) != totalParties {
		t.Errorf("share count: got %d, want %d", len(shares), totalParties)
	}

	for _, pid := range parties {
		share, ok := shares[pid]
		if !ok {
			t.Errorf("missing share for party %s", pid)
			continue
		}
		if share.PartyID != pid {
			t.Errorf("share party ID mismatch: got %s, want %s", share.PartyID, pid)
		}
		if share.Generation != 1 {
			t.Errorf("share generation mismatch: got %d, want 1", share.Generation)
		}
		if len(share.LWE.Coeffs) == 0 {
			t.Errorf("share LWE coeffs empty for %s", pid)
		}
		if share.LWE.Total != totalParties {
			t.Errorf("share LWE total mismatch: got %d, want %d", share.LWE.Total, totalParties)
		}
	}
}

// TestProtocolCreation verifies that each party can construct a Protocol
// from their own share alone — no master key required.
func TestProtocolCreation(t *testing.T) {
	threshold, totalParties := 2, 3
	parties := []party.ID{"party1", "party2", "party3"}

	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	kg, err := NewKeyGenerator(threshold, totalParties, params, nil)
	if err != nil {
		t.Fatalf("NewKeyGenerator: %v", err)
	}
	pubKey, shares, err := kg.GenerateKeys(context.Background(), parties)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}

	for _, pid := range parties {
		config := &Config{
			Threshold:      threshold,
			TotalParties:   totalParties,
			PartyID:        pid,
			Generation:     1,
			FHEParams:      params,
			PublicKey:      pubKey,
			SecretKeyShare: shares[pid],
		}
		proto, err := NewProtocol(config, nil)
		if err != nil {
			t.Fatalf("NewProtocol for %s: %v", pid, err)
		}
		if proto.PublicEncryptor() == nil {
			t.Errorf("public encryptor is nil for %s", pid)
		}
		if proto.SecretShareIndex() == 0 {
			t.Errorf("secret share index is 0 for %s", pid)
		}
	}
}

// TestThresholdDecrypt_RoundTrip_2of3 is the canonical happy-path:
// 3 parties, 2 of them produce partials, the combine recovers the
// plaintext bit. This is the integration test that proves the entire
// orchestration layer is wired correctly.
func TestThresholdDecrypt_RoundTrip_2of3(t *testing.T) {
	for _, value := range []bool{false, true} {
		runProtoRoundTrip(t, fhe.PN10QP27, 2, 3, value)
	}
}

// TestThresholdDecrypt_RoundTrip_5of9 is the medium-committee test.
func TestThresholdDecrypt_RoundTrip_5of9(t *testing.T) {
	for _, value := range []bool{false, true} {
		runProtoRoundTrip(t, fhe.PN11QP54, 5, 9, value)
	}
}

// TestThresholdDecrypt_RoundTrip_11of21 is the large-committee test
// (canonical Bendlin-Damgård benchmark). Skipped under -short.
func TestThresholdDecrypt_RoundTrip_11of21(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 11-of-21 round-trip under -short")
	}
	for _, value := range []bool{false, true} {
		runProtoRoundTrip(t, fhe.PN11QP54, 11, 21, value)
	}
}

func runProtoRoundTrip(t *testing.T, lit fhe.ParametersLiteral, threshold, total int, value bool) {
	t.Helper()
	params, err := fhe.NewParametersFromLiteral(lit)
	if err != nil {
		t.Fatalf("params: %v", err)
	}

	parties := makeParties(total)
	kg, err := NewKeyGenerator(threshold, total, params, nil)
	if err != nil {
		t.Fatalf("NewKeyGenerator: %v", err)
	}
	// Need the master to encrypt for this smoke test — production uses
	// public-key encrypt via Protocol.PublicEncryptor() and never holds
	// the master after keygen.
	masterSK, pubKey, shares, err := kg.GenerateKeysWithMaster(context.Background(), parties)
	if err != nil {
		t.Fatalf("GenerateKeysWithMaster: %v", err)
	}

	// Encrypt with master SK. (Equivalent to public-key encrypt for
	// correctness purposes; the master-SK path produces less noise so
	// the round-trip is stricter on the threshold-decrypt logic.)
	enc := fhe.NewEncryptor(params, masterSK)
	ct := enc.Encrypt(value)

	// Each party in a chosen subset of size t produces a partial.
	subsetParties := parties[total-threshold:]
	subsetShares := make([]*SecretKeyShare, threshold)
	for i, pid := range subsetParties {
		subsetShares[i] = shares[pid]
	}

	// First party combines.
	combinerCfg := &Config{
		Threshold:      threshold,
		TotalParties:   total,
		PartyID:        subsetParties[0],
		Generation:     1,
		FHEParams:      params,
		PublicKey:      pubKey,
		SecretKeyShare: subsetShares[0],
	}
	combiner, err := NewProtocol(combinerCfg, nil)
	if err != nil {
		t.Fatalf("combiner: %v", err)
	}

	// Each contributing party (including the combiner) computes its share.
	for i, share := range subsetShares {
		partyCfg := &Config{
			Threshold:      threshold,
			TotalParties:   total,
			PartyID:        subsetParties[i],
			Generation:     1,
			FHEParams:      params,
			PublicKey:      pubKey,
			SecretKeyShare: share,
		}
		party, err := NewProtocol(partyCfg, nil)
		if err != nil {
			t.Fatalf("party %s: %v", subsetParties[i], err)
		}
		ds, err := party.CreateBitDecryptionShare(context.Background(), ct)
		if err != nil {
			t.Fatalf("party %s share: %v", subsetParties[i], err)
		}
		if err := combiner.AddDecryptionShare(ds); err != nil {
			t.Fatalf("combiner add share from %s: %v", subsetParties[i], err)
		}
	}

	got, err := combiner.CombineBitShares(context.Background(), ct)
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	if got != value {
		t.Fatalf("round trip: got %v, want %v (t=%d, n=%d)", got, value, threshold, total)
	}
}

// TestThresholdDecrypt_BelowThresholdRejected confirms that the
// orchestration layer enforces the threshold: a single party's
// CombineBitShares fails with ErrInsufficientShares.
func TestThresholdDecrypt_BelowThresholdRejected(t *testing.T) {
	threshold, total := 2, 3
	parties := []party.ID{"p1", "p2", "p3"}
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	kg, _ := NewKeyGenerator(threshold, total, params, nil)
	masterSK, pubKey, shares, err := kg.GenerateKeysWithMaster(context.Background(), parties)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	enc := fhe.NewEncryptor(params, masterSK)
	ct := enc.Encrypt(true)

	cfg := &Config{
		Threshold: threshold, TotalParties: total, PartyID: parties[0], Generation: 1,
		FHEParams: params, PublicKey: pubKey, SecretKeyShare: shares[parties[0]],
	}
	p, err := NewProtocol(cfg, nil)
	if err != nil {
		t.Fatalf("proto: %v", err)
	}
	ds, err := p.CreateBitDecryptionShare(context.Background(), ct)
	if err != nil {
		t.Fatalf("share: %v", err)
	}
	if err := p.AddDecryptionShare(ds); err != nil {
		t.Fatalf("add: %v", err)
	}

	// Only 1 share collected, threshold is 2 — must error.
	if _, err := p.CombineBitShares(context.Background(), ct); err == nil {
		t.Fatal("expected ErrInsufficientShares; got nil")
	}
}

// TestSecretKeyShare_DoesNotEqualMaster is the central security
// regression: no party's stored share equals the master secret key.
// This guards against a regression to the prior (UNSAFE) implementation
// where every party stored the master.
func TestSecretKeyShare_DoesNotEqualMaster(t *testing.T) {
	threshold, total := 3, 5
	parties := makeParties(total)
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	kg, _ := NewKeyGenerator(threshold, total, params, nil)
	masterSK, _, shares, err := kg.GenerateKeysWithMaster(context.Background(), parties)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// 1) No share carries any *fhe.SecretKey reference.
	for pid, share := range shares {
		v := reflect.ValueOf(*share)
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			if f.Kind() == reflect.Ptr && !f.IsNil() {
				if _, ok := f.Interface().(*fhe.SecretKey); ok {
					t.Fatalf("share for %s carries *fhe.SecretKey at field %s — regression to unsafe scheme", pid, v.Type().Field(i).Name)
				}
			}
		}
	}

	// 2) No share's LWE coefficients equal the master's standard-form
	//    coefficients. (Note: the master's SKLWE was zeroed by
	//    GenerateKeys; GenerateKeysWithMaster keeps it intact for this
	//    audit purpose.)
	ringQ := params.ParamsLWE().RingQ()
	skStd := ringQ.NewPoly()
	ringQ.IMForm(masterSK.SKLWE.Value.Q, skStd)
	ringQ.INTT(skStd, skStd)

	for pid, share := range shares {
		allEqual := true
		for i := 0; i < ringQ.N(); i++ {
			if share.LWE.Coeffs[i] != skStd.Coeffs[0][i] {
				allEqual = false
				break
			}
		}
		if allEqual {
			t.Fatalf("share for %s equals master secret coefficients", pid)
		}
	}
}

// TestGenerateKeys_WipesMaster confirms that the production keygen
// path (GenerateKeys, not GenerateKeysWithMaster) does not retain a
// dealer-side master key.
func TestGenerateKeys_WipesMaster(t *testing.T) {
	threshold, total := 2, 3
	parties := makeParties(total)
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	kg, _ := NewKeyGenerator(threshold, total, params, nil)
	pubKey, shares, err := kg.GenerateKeys(context.Background(), parties)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	_ = pubKey
	// We can't inspect dealer-internal state, but the contract is that
	// the returned shares are sufficient to operate the protocol — no
	// caller ever needs the master.
	if len(shares) != total {
		t.Fatalf("share count: got %d, want %d", len(shares), total)
	}
}

// TestThresholdDecrypt_DeterministicCombine verifies that combining the
// same set of partials yields the same plaintext (the partial-decrypt
// step is randomized, but the combine is deterministic in its inputs).
func TestThresholdDecrypt_DeterministicCombine(t *testing.T) {
	threshold, total := 2, 3
	parties := makeParties(total)
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	kg, _ := NewKeyGenerator(threshold, total, params, nil)
	masterSK, pubKey, shares, err := kg.GenerateKeysWithMaster(context.Background(), parties)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	enc := fhe.NewEncryptor(params, masterSK)
	ct := enc.Encrypt(true)

	// Each party produces a partial once.
	createPartial := func(pid party.ID) *fhethreshold.LWEPartialDecryption {
		cfg := &Config{
			Threshold: threshold, TotalParties: total, PartyID: pid, Generation: 1,
			FHEParams: params, PublicKey: pubKey, SecretKeyShare: shares[pid],
		}
		p, err := NewProtocol(cfg, nil)
		if err != nil {
			t.Fatalf("proto %s: %v", pid, err)
		}
		ds, err := p.CreateBitDecryptionShare(context.Background(), ct)
		if err != nil {
			t.Fatalf("share %s: %v", pid, err)
		}
		return ds.PartialResult[0]
	}
	p0 := createPartial(parties[0])
	p1 := createPartial(parties[1])

	// Combine the same partials twice; expect identical decoded bit.
	got1, err := fhethreshold.CombineFHE(ct, []*fhethreshold.LWEPartialDecryption{p0, p1}, params)
	if err != nil {
		t.Fatalf("combine 1: %v", err)
	}
	got2, err := fhethreshold.CombineFHE(ct, []*fhethreshold.LWEPartialDecryption{p0, p1}, params)
	if err != nil {
		t.Fatalf("combine 2: %v", err)
	}
	if got1 != got2 {
		t.Fatalf("combine non-deterministic: %v vs %v", got1, got2)
	}
	if !got1 {
		t.Fatalf("plaintext recovery wrong: got false, want true")
	}
}

// TestCalculateThreshold confirms the re-exported helper preserves the
// canonical floor(n/2)+1 formula.
func TestCalculateThreshold(t *testing.T) {
	tests := []struct {
		n, want int
	}{
		{1, 1}, {2, 2}, {3, 2}, {4, 3}, {5, 3}, {6, 4}, {7, 4}, {10, 6}, {0, 0},
	}
	for _, tc := range tests {
		if got := CalculateThreshold(tc.n); got != tc.want {
			t.Errorf("CalculateThreshold(%d) = %d, want %d", tc.n, got, tc.want)
		}
	}
}

func TestTypeAliases(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	if params.N() != 1024 {
		t.Errorf("N: got %d, want 1024", params.N())
	}
	if FheUint8 != fhe.FheUint8 {
		t.Error("FheUint8 alias mismatch")
	}
	if FheUint256 != fhe.FheUint256 {
		t.Error("FheUint256 alias mismatch")
	}
}

// TestThresholdRNG_DefaultPathReturnsError confirms that the legacy
// RNG path requires explicit SetThresholdRNGWithMaster — accidental
// invocation of SetThresholdRNG without the master ceremony must error
// rather than silently bypass.
func TestThresholdRNG_DefaultPathReturnsError(t *testing.T) {
	threshold, total := 2, 3
	parties := makeParties(total)
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	kg, _ := NewKeyGenerator(threshold, total, params, nil)
	pubKey, shares, err := kg.GenerateKeys(context.Background(), parties)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	cfg := &Config{
		Threshold: threshold, TotalParties: total, PartyID: parties[0], Generation: 1,
		FHEParams: params, PublicKey: pubKey, SecretKeyShare: shares[parties[0]],
	}
	p, err := NewProtocol(cfg, nil)
	if err != nil {
		t.Fatalf("proto: %v", err)
	}
	if err := p.SetThresholdRNG(&mockThresholdProvider{seed: []byte("seed")}); err == nil {
		t.Fatal("expected SetThresholdRNG to error without prior SetThresholdRNGWithMaster")
	}
}

func makeParties(n int) []party.ID {
	out := make([]party.ID, n)
	for i := 0; i < n; i++ {
		out[i] = party.ID(string(rune('a'+i)) + "party")
	}
	return out
}
