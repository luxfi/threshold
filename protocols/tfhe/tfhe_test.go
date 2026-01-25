package tfhe

import (
	"context"
	"testing"

	"github.com/luxfi/fhe"
	"github.com/luxfi/threshold/pkg/party"
)

// mockThresholdProvider is a local mock implementation for testing
type mockThresholdProvider struct {
	seed []byte
}

func (m *mockThresholdProvider) RequestRandomness(ctx context.Context, numBytes int) ([]byte, error) {
	// Return deterministic randomness based on seed
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

	// Set up local threshold provider (using mock for testing)
	localProvider := &mockThresholdProvider{seed: []byte("test-seed")}
	proto.SetThresholdRNG(localProvider)

	// Verify threshold network is available
	ctx := context.Background()
	if !proto.IsThresholdNetworkAvailable(ctx) {
		t.Error("threshold network should be available with local provider")
	}
}

func TestCalculateThreshold(t *testing.T) {
	// CalculateThreshold(n) returns floor(n/2) + 1 for honest majority
	tests := []struct {
		numParties int
		expected   int
	}{
		{1, 1},  // floor(1/2) + 1 = 0 + 1 = 1
		{2, 2},  // floor(2/2) + 1 = 1 + 1 = 2
		{3, 2},  // floor(3/2) + 1 = 1 + 1 = 2
		{4, 3},  // floor(4/2) + 1 = 2 + 1 = 3
		{5, 3},  // floor(5/2) + 1 = 2 + 1 = 3
		{6, 4},  // floor(6/2) + 1 = 3 + 1 = 4
		{7, 4},  // floor(7/2) + 1 = 3 + 1 = 4
		{10, 6}, // floor(10/2) + 1 = 5 + 1 = 6
		{0, 0},  // edge case: n <= 0 returns 0
	}

	for _, tc := range tests {
		result := CalculateThreshold(tc.numParties)
		if result != tc.expected {
			t.Errorf("CalculateThreshold(%d) = %d, expected %d",
				tc.numParties, result, tc.expected)
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
