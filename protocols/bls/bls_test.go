package bls_test

import (
	"crypto/rand"
	"testing"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
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

func TestBLSSign(t *testing.T) {
	// Generate a test key using DirectSecretKey
	directSk, err := bls.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Get public key
	directPk := directSk.PublicKey()

	// Convert to regular types for our API
	skBytes := directSk.Bytes()
	sk, err := bls.SecretKeyFromBytes(skBytes)
	require.NoError(t, err)

	pkBytes := directPk.Bytes()
	pk, err := bls.PublicKeyFromCompressedBytes(pkBytes)
	require.NoError(t, err)

	// Create config with the key
	cfg := &blsThreshold.Config{
		ID:          party.ID("alice"),
		Threshold:   2,
		PublicKey:   pk,
		SecretShare: sk,
		VerificationKeys: map[party.ID]*bls.PublicKey{
			"alice": pk,
		},
	}

	// Sign a message
	message := []byte("test message for BLS signing")
	sig, err := cfg.Sign(message)
	require.NoError(t, err)
	require.NotNil(t, sig)

	// Verify the signature
	valid := cfg.VerifyAggregateSignature(message, sig)
	assert.True(t, valid, "Signature should be valid")
}

func TestBLSAggregation(t *testing.T) {
	threshold := 3
	n := 5

	// Generate keys for all parties
	signatures := make([]*bls.Signature, 0, n)

	message := []byte("test message for aggregation")

	for i := 0; i < n; i++ {
		// Generate key
		directSk, err := bls.GenerateKey(rand.Reader)
		require.NoError(t, err)

		// Convert to regular secret key
		skBytes := directSk.Bytes()
		sk, err := bls.SecretKeyFromBytes(skBytes)
		require.NoError(t, err)

		// Sign the message
		sig := sk.Sign(message)
		signatures = append(signatures, sig)
	}

	// Aggregate threshold signatures
	aggregatedSig, err := blsThreshold.AggregateSignatures(signatures[:threshold], threshold)
	require.NoError(t, err)
	require.NotNil(t, aggregatedSig)

	// For verification, we would need the aggregated public key
	// This is just testing the aggregation function works
}

func TestBLSVerifyPartialSignature(t *testing.T) {
	// Generate keys for multiple parties
	parties := []party.ID{"alice", "bob", "charlie"}
	verificationKeys := make(map[party.ID]*bls.PublicKey)

	var aliceSk *bls.SecretKey

	for _, id := range parties {
		directSk, err := bls.GenerateKey(rand.Reader)
		require.NoError(t, err)

		// Get public key
		directPk := directSk.PublicKey()
		pkBytes := directPk.Bytes()
		pk, err := bls.PublicKeyFromCompressedBytes(pkBytes)
		require.NoError(t, err)

		verificationKeys[id] = pk

		// Save alice's secret key
		if id == "alice" {
			skBytes := directSk.Bytes()
			aliceSk, err = bls.SecretKeyFromBytes(skBytes)
			require.NoError(t, err)
		}
	}

	// Create config for alice
	cfg := &blsThreshold.Config{
		ID:               "alice",
		Threshold:        2,
		SecretShare:      aliceSk,
		VerificationKeys: verificationKeys,
	}

	message := []byte("test partial signature")
	sig := aliceSk.Sign(message)

	// Verify alice's signature
	valid := cfg.VerifyPartialSignature("alice", message, sig)
	assert.True(t, valid, "Alice's signature should be valid")

	// Try to verify with wrong party ID
	valid = cfg.VerifyPartialSignature("bob", message, sig)
	assert.False(t, valid, "Signature should not verify for wrong party")
}

func TestBLSKeygenProtocol(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	selfID := party.ID("alice")
	participants := []party.ID{"alice", "bob", "charlie"}
	threshold := 2

	// Get the keygen start function
	startFunc := blsThreshold.Keygen(selfID, participants, threshold, pl)
	require.NotNil(t, startFunc)

	// Try to start the protocol (it's not implemented yet)
	sessionID := []byte("test-bls-keygen")
	session, err := startFunc(sessionID)

	// We expect an error since it's not implemented
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
	assert.Nil(t, session)
}

func TestBLSSignProtocol(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	// Create a test config
	directSk, err := bls.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Convert keys
	skBytes := directSk.Bytes()
	sk, err := bls.SecretKeyFromBytes(skBytes)
	require.NoError(t, err)

	directPk := directSk.PublicKey()
	pkBytes := directPk.Bytes()
	pk, err := bls.PublicKeyFromCompressedBytes(pkBytes)
	require.NoError(t, err)

	cfg := &blsThreshold.Config{
		ID:          party.ID("alice"),
		Threshold:   2,
		PublicKey:   pk,
		SecretShare: sk,
	}

	signers := []party.ID{"alice", "bob"}
	message := []byte("test protocol message")

	// Get the sign protocol start function
	startFunc := blsThreshold.SignProtocol(cfg, signers, message, pl)
	require.NotNil(t, startFunc)

	// Try to start the protocol (it's not implemented yet)
	sessionID := []byte("test-bls-sign")
	session, err := startFunc(sessionID)

	// We expect an error since it's not implemented
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
	assert.Nil(t, session)
}

func TestBLSThresholdValidation(t *testing.T) {
	// Test insufficient signatures for threshold
	threshold := 3
	signatures := []*bls.Signature{}

	// Try to aggregate with insufficient signatures
	_, err := blsThreshold.AggregateSignatures(signatures, threshold)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient signatures")

	// Generate one signature
	directSk, err := bls.GenerateKey(rand.Reader)
	require.NoError(t, err)

	skBytes := directSk.Bytes()
	sk, err := bls.SecretKeyFromBytes(skBytes)
	require.NoError(t, err)

	message := []byte("test")
	sig := sk.Sign(message)
	signatures = append(signatures, sig)

	// Still insufficient
	_, err = blsThreshold.AggregateSignatures(signatures, threshold)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient signatures")
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

	// Verify should fail for unknown party
	cfg.VerificationKeys = make(map[party.ID]*bls.PublicKey)
	valid := cfg.VerifyPartialSignature("unknown", message, nil)
	assert.False(t, valid, "Should fail for unknown party")
}
