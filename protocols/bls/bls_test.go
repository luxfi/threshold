package bls_test

import (
	"context"
	"testing"

	"github.com/luxfi/threshold/pkg/party"
	blsThreshold "github.com/luxfi/threshold/protocols/bls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBLSConfig(t *testing.T) {
	// Create a test configuration
	cfg := &blsThreshold.Config{
		ID:        party.ID("alice"),
		Threshold: 2,
	}

	assert.Equal(t, party.ID("alice"), cfg.ID)
	assert.Equal(t, 2, cfg.Threshold)
}

func TestThresholdBLS_2of3(t *testing.T) {
	ctx := context.Background()

	// Create party IDs (must be non-zero for polynomial evaluation)
	parties := []party.ID{
		party.ID("party1"),
		party.ID("party2"),
		party.ID("party3"),
	}

	// Generate threshold key shares
	dealer := &blsThreshold.TrustedDealer{
		Threshold:    2, // Need 2 signatures to reconstruct
		TotalParties: 3,
	}

	shares, groupPK, err := dealer.GenerateShares(ctx, parties)
	require.NoError(t, err)
	require.NotNil(t, groupPK)
	require.Len(t, shares, 3)

	// Get verification keys
	verificationKeys := blsThreshold.GetVerificationKeys(shares)

	// Create configs for each party
	configs := make(map[party.ID]*blsThreshold.Config, 3)
	for _, id := range parties {
		configs[id] = blsThreshold.NewConfig(id, 2, 3, shares[id], groupPK, verificationKeys)
	}

	// Test message
	message := []byte("test message for threshold BLS")

	// Each party signs
	sigShares := make([]*blsThreshold.SignatureShare, 0, 3)
	for _, id := range parties {
		share, err := configs[id].Sign(message)
		require.NoError(t, err, "party %s signing failed", id)
		require.NotNil(t, share.Signature)
		sigShares = append(sigShares, share)
	}

	// Verify each partial signature
	for _, share := range sigShares {
		valid := configs[parties[0]].VerifyPartialSignature(share, message)
		require.True(t, valid, "partial signature from %s should be valid", share.PartyID)
	}

	// Aggregate with 2 of 3 signatures (threshold)
	aggSig, err := blsThreshold.AggregateSignatures(sigShares[:2], 2)
	require.NoError(t, err)
	require.NotNil(t, aggSig)

	// Verify aggregate signature
	valid := configs[parties[0]].VerifyAggregateSignature(message, aggSig)
	require.True(t, valid, "aggregate signature should verify against group key")

	// Try with different 2 parties
	differentShares := []*blsThreshold.SignatureShare{sigShares[0], sigShares[2]}
	aggSig2, err := blsThreshold.AggregateSignatures(differentShares, 2)
	require.NoError(t, err)
	valid = configs[parties[0]].VerifyAggregateSignature(message, aggSig2)
	require.True(t, valid, "aggregate from different parties should also verify")

	// Wrong message should fail verification
	require.False(t, configs[parties[0]].VerifyAggregateSignature([]byte("wrong message"), aggSig))
}

func TestThresholdBLS_3of5(t *testing.T) {
	ctx := context.Background()

	parties := make([]party.ID, 5)
	for i := range parties {
		parties[i] = party.ID([]byte{byte(i + 1)})
	}

	dealer := &blsThreshold.TrustedDealer{
		Threshold:    3,
		TotalParties: 5,
	}

	shares, groupPK, err := dealer.GenerateShares(ctx, parties)
	require.NoError(t, err)

	verificationKeys := blsThreshold.GetVerificationKeys(shares)

	configs := make(map[party.ID]*blsThreshold.Config, 5)
	for _, id := range parties {
		configs[id] = blsThreshold.NewConfig(id, 3, 5, shares[id], groupPK, verificationKeys)
	}

	message := []byte("threshold 3 of 5 test")

	sigShares := make([]*blsThreshold.SignatureShare, 0, 5)
	for _, id := range parties {
		share, err := configs[id].Sign(message)
		require.NoError(t, err)
		sigShares = append(sigShares, share)
	}

	// Need exactly 3 signatures
	aggSig, err := blsThreshold.AggregateSignatures(sigShares[:3], 3)
	require.NoError(t, err)

	valid := configs[parties[0]].VerifyAggregateSignature(message, aggSig)
	require.True(t, valid)

	// With 2 signatures should fail
	_, err = blsThreshold.AggregateSignatures(sigShares[:2], 3)
	require.Error(t, err)
}

func TestThresholdBLS_InsufficientShares(t *testing.T) {
	ctx := context.Background()

	parties := []party.ID{party.ID("a"), party.ID("b"), party.ID("c")}

	dealer := &blsThreshold.TrustedDealer{
		Threshold:    2,
		TotalParties: 3,
	}

	shares, groupPK, err := dealer.GenerateShares(ctx, parties)
	require.NoError(t, err)

	verificationKeys := blsThreshold.GetVerificationKeys(shares)

	config := blsThreshold.NewConfig(parties[0], 2, 3, shares[parties[0]], groupPK, verificationKeys)

	message := []byte("test")
	share, err := config.Sign(message)
	require.NoError(t, err)

	// Try to aggregate with only 1 share (need 2)
	_, err = blsThreshold.AggregateSignatures([]*blsThreshold.SignatureShare{share}, 2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "insufficient")
}

func TestBLSConfigValidation(t *testing.T) {
	cfg := &blsThreshold.Config{
		ID:          party.ID("alice"),
		Threshold:   2,
		SecretShare: nil, // No secret share
	}

	message := []byte("test")

	// Should fail to sign without secret share
	_, err := cfg.Sign(message)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no secret share available")
}
