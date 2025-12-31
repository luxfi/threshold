package tfhe

import (
	"context"
	"testing"

	"github.com/luxfi/fhe"
	"github.com/luxfi/threshold/pkg/party"
)

func TestKeyGeneration(t *testing.T) {
	threshold := 2
	totalParties := 3
	parties := []party.ID{"party1", "party2", "party3"}

	// Create FHE parameters
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral failed: %v", err)
	}

	kg, err := NewKeyGenerator(threshold, totalParties, params, nil)
	if err != nil {
		t.Fatalf("NewKeyGenerator failed: %v", err)
	}

	pubKey, shares, err := kg.GenerateKeys(context.Background(), parties)
	if err != nil {
		t.Fatalf("GenerateKeys failed: %v", err)
	}

	if pubKey == nil {
		t.Fatal("public key is nil")
	}

	if len(shares) != totalParties {
		t.Errorf("expected %d shares, got %d", totalParties, len(shares))
	}

	for _, pid := range parties {
		share, ok := shares[pid]
		if !ok {
			t.Errorf("missing share for party %s", pid)
			continue
		}
		if share.PartyID != pid {
			t.Errorf("share party ID mismatch: expected %s, got %s", pid, share.PartyID)
		}
		if share.Generation != 1 {
			t.Errorf("share generation mismatch: expected 1, got %d", share.Generation)
		}
		if share.UnderlyingKey == nil {
			t.Errorf("share underlying key is nil for %s", pid)
		}
	}
}

func TestProtocolCreation(t *testing.T) {
	threshold := 2
	totalParties := 3
	parties := []party.ID{"party1", "party2", "party3"}

	// Create FHE parameters
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral failed: %v", err)
	}

	// Generate keys
	kg, err := NewKeyGenerator(threshold, totalParties, params, nil)
	if err != nil {
		t.Fatalf("NewKeyGenerator failed: %v", err)
	}

	pubKey, shares, err := kg.GenerateKeys(context.Background(), parties)
	if err != nil {
		t.Fatalf("GenerateKeys failed: %v", err)
	}

	// Create protocol for each party
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
			t.Fatalf("NewProtocol failed for %s: %v", pid, err)
		}

		if proto.GetEncryptor() == nil {
			t.Errorf("encryptor is nil for %s", pid)
		}
		if proto.GetDecryptor() == nil {
			t.Errorf("decryptor is nil for %s", pid)
		}
	}
}

func TestThresholdRNGLocal(t *testing.T) {
	threshold := 2
	totalParties := 3
	parties := []party.ID{"party1", "party2", "party3"}

	// Create FHE parameters
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral failed: %v", err)
	}

	// Generate keys
	kg, err := NewKeyGenerator(threshold, totalParties, params, nil)
	if err != nil {
		t.Fatalf("NewKeyGenerator failed: %v", err)
	}

	pubKey, shares, err := kg.GenerateKeys(context.Background(), parties)
	if err != nil {
		t.Fatalf("GenerateKeys failed: %v", err)
	}

	// Create protocol with local threshold provider
	config := &Config{
		Threshold:      threshold,
		TotalParties:   totalParties,
		PartyID:        parties[0],
		Generation:     1,
		FHEParams:      params,
		PublicKey:      pubKey,
		SecretKeyShare: shares[parties[0]],
	}

	proto, err := NewProtocol(config, nil)
	if err != nil {
		t.Fatalf("NewProtocol failed: %v", err)
	}

	// Set up local threshold provider
	localProvider := fhe.NewLocalThresholdProvider(threshold, totalParties, []byte("test-seed"))
	proto.SetThresholdRNG(localProvider)

	// Verify threshold network is available
	ctx := context.Background()
	if !proto.IsThresholdNetworkAvailable(ctx) {
		t.Error("threshold network should be available with local provider")
	}
}

func TestCalculateThreshold(t *testing.T) {
	tests := []struct {
		percent    int
		numParties int
		expected   int
	}{
		{69, 5, 4},  // 69% of 5 = 3.45, ceil = 4
		{50, 4, 2},  // 50% of 4 = 2
		{75, 8, 6},  // 75% of 8 = 6
		{100, 3, 3}, // 100% of 3 = 3
		{0, 5, 1},   // 0% should return at least 1
	}

	for _, tc := range tests {
		result := CalculateThreshold(tc.percent, tc.numParties)
		if result != tc.expected {
			t.Errorf("CalculateThreshold(%d, %d) = %d, expected %d",
				tc.percent, tc.numParties, result, tc.expected)
		}
	}
}

func TestTypeAliases(t *testing.T) {
	// Verify type aliases work correctly
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral with alias failed: %v", err)
	}

	if params.N() != 1024 {
		t.Errorf("expected N=1024, got %d", params.N())
	}

	// Verify integer type constants
	if FheUint8 != fhe.FheUint8 {
		t.Error("FheUint8 alias mismatch")
	}
	if FheUint256 != fhe.FheUint256 {
		t.Error("FheUint256 alias mismatch")
	}
}
