package quasar_test

import (
	"context"
	"testing"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/quasar"
	"github.com/stretchr/testify/require"
)

func TestQuasarKeyGeneration(t *testing.T) {
	ctx := context.Background()

	parties := []party.ID{
		party.ID("party1"),
		party.ID("party2"),
		party.ID("party3"),
	}

	dealer := &quasar.TrustedDealer{
		Threshold:    2,
		TotalParties: 3,
	}

	configs, groupKey, err := dealer.GenerateShares(ctx, parties)
	require.NoError(t, err)
	require.Len(t, configs, 3)
	require.NotNil(t, groupKey)
	require.NotNil(t, groupKey.BLS)
	require.NotNil(t, groupKey.Corona)

	// Verify each party has valid config
	for _, id := range parties {
		cfg := configs[id]
		require.Equal(t, id, cfg.ID)
		require.Equal(t, 2, cfg.Threshold)
		require.Equal(t, 3, cfg.TotalParties)
		require.NotNil(t, cfg.BLSSecretShare)
		require.NotNil(t, cfg.BLSPublicKey)
		require.NotNil(t, cfg.CoronaShare)
	}
}

func TestQuasarBLSOnlySign(t *testing.T) {
	ctx := context.Background()

	parties := []party.ID{
		party.ID("party1"),
		party.ID("party2"),
		party.ID("party3"),
	}

	dealer := &quasar.TrustedDealer{
		Threshold:    2,
		TotalParties: 3,
	}

	configs, groupKey, err := dealer.GenerateShares(ctx, parties)
	require.NoError(t, err)

	message := []byte("test message for Quasar BLS-only signing")

	// Create protocols
	protocols := make(map[party.ID]*quasar.Protocol, 3)
	for _, id := range parties {
		proto, err := quasar.NewProtocol(configs[id])
		require.NoError(t, err)
		protocols[id] = proto
	}

	// Each party signs (BLS only, no signer indices for Corona)
	shares := make([]*quasar.SignatureShare, 0, 3)
	for _, id := range parties {
		share, err := protocols[id].Sign(ctx, message, 1, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, share.BLSShare)
		shares = append(shares, share)
	}

	// Collect shares on first party's protocol
	proto := protocols[parties[0]]
	for _, share := range shares {
		proto.AddShare(share)
	}

	require.True(t, proto.CanFinalize())

	// Finalize
	sig, err := proto.Finalize(message)
	require.NoError(t, err)
	require.True(t, sig.HasBLS())
	require.False(t, sig.HasCorona()) // No Corona without signer indices

	// Verify BLS only
	valid := quasar.VerifyBLSOnly(groupKey.BLS, message, sig)
	require.True(t, valid)

	// Full verification (BLS only since no Corona)
	valid, err = quasar.Verify(groupKey, message, sig)
	require.NoError(t, err)
	require.True(t, valid)
}

func TestQuasarThreshold2of3(t *testing.T) {
	ctx := context.Background()

	parties := []party.ID{
		party.ID("party1"),
		party.ID("party2"),
		party.ID("party3"),
	}

	dealer := &quasar.TrustedDealer{
		Threshold:    2,
		TotalParties: 3,
	}

	configs, groupKey, err := dealer.GenerateShares(ctx, parties)
	require.NoError(t, err)

	message := []byte("test 2-of-3 threshold signing")

	// Create protocols
	protocols := make(map[party.ID]*quasar.Protocol, 3)
	for _, id := range parties {
		proto, err := quasar.NewProtocol(configs[id])
		require.NoError(t, err)
		protocols[id] = proto
	}

	// Only 2 parties sign (threshold)
	signingParties := parties[:2]
	shares := make([]*quasar.SignatureShare, 0, 2)
	for _, id := range signingParties {
		share, err := protocols[id].Sign(ctx, message, 1, nil, nil)
		require.NoError(t, err)
		shares = append(shares, share)
	}

	// Collect shares
	proto := protocols[parties[0]]
	for _, share := range shares {
		proto.AddShare(share)
	}

	require.Equal(t, 2, proto.BLSShareCount())
	require.True(t, proto.CanFinalize())

	// Finalize with only 2 shares
	sig, err := proto.Finalize(message)
	require.NoError(t, err)
	require.NotNil(t, sig)

	// Verify
	valid, err := quasar.Verify(groupKey, message, sig)
	require.NoError(t, err)
	require.True(t, valid)
}

func TestQuasarInsufficientShares(t *testing.T) {
	ctx := context.Background()

	parties := []party.ID{
		party.ID("party1"),
		party.ID("party2"),
		party.ID("party3"),
	}

	dealer := &quasar.TrustedDealer{
		Threshold:    2,
		TotalParties: 3,
	}

	configs, _, err := dealer.GenerateShares(ctx, parties)
	require.NoError(t, err)

	message := []byte("test insufficient shares")

	// Create protocol and sign with only 1 party
	proto, err := quasar.NewProtocol(configs[parties[0]])
	require.NoError(t, err)

	share, err := proto.Sign(ctx, message, 1, nil, nil)
	require.NoError(t, err)
	proto.AddShare(share)

	require.False(t, proto.CanFinalize())

	// Should fail to finalize
	_, err = proto.Finalize(message)
	require.Error(t, err)
	require.ErrorIs(t, err, quasar.ErrInsufficientShares)
}

func TestQuasarProtocolCreation(t *testing.T) {
	ctx := context.Background()

	parties := []party.ID{party.ID("party1"), party.ID("party2"), party.ID("party3")}

	dealer := &quasar.TrustedDealer{
		Threshold:    2,
		TotalParties: 3,
	}

	configs, _, err := dealer.GenerateShares(ctx, parties)
	require.NoError(t, err)

	// Valid creation
	proto, err := quasar.NewProtocol(configs[parties[0]])
	require.NoError(t, err)
	require.NotNil(t, proto)

	// Nil config should fail
	_, err = quasar.NewProtocol(nil)
	require.Error(t, err)
	require.ErrorIs(t, err, quasar.ErrNotInitialized)

	// Missing BLS share should fail
	badConfig := &quasar.Config{
		ID:        party.ID("test"),
		Threshold: 2,
	}
	_, err = quasar.NewProtocol(badConfig)
	require.Error(t, err)
}

func TestQuasarSignatureBytes(t *testing.T) {
	ctx := context.Background()

	parties := []party.ID{
		party.ID("party1"),
		party.ID("party2"),
		party.ID("party3"),
	}

	dealer := &quasar.TrustedDealer{
		Threshold:    2,
		TotalParties: 3,
	}

	configs, _, err := dealer.GenerateShares(ctx, parties)
	require.NoError(t, err)

	message := []byte("test serialization")

	// Sign with enough parties (2 of 3)
	protocols := make(map[party.ID]*quasar.Protocol, 3)
	for _, id := range parties {
		proto, err := quasar.NewProtocol(configs[id])
		require.NoError(t, err)
		protocols[id] = proto
	}

	// Only need threshold (2) parties
	for _, id := range parties[:2] {
		share, err := protocols[id].Sign(ctx, message, 1, nil, nil)
		require.NoError(t, err)
		protocols[parties[0]].AddShare(share)
	}

	sig, err := protocols[parties[0]].Finalize(message)
	require.NoError(t, err)

	// Serialize
	sigBytes, err := sig.Bytes()
	require.NoError(t, err)
	require.NotEmpty(t, sigBytes)

	// First byte should be flags (0x00 for BLS-only)
	require.Equal(t, byte(0x00), sigBytes[0])
}

func TestQuasarClearShares(t *testing.T) {
	ctx := context.Background()

	parties := []party.ID{party.ID("party1"), party.ID("party2"), party.ID("party3")}

	dealer := &quasar.TrustedDealer{
		Threshold:    2,
		TotalParties: 3,
	}

	configs, _, err := dealer.GenerateShares(ctx, parties)
	require.NoError(t, err)

	proto, err := quasar.NewProtocol(configs[parties[0]])
	require.NoError(t, err)

	// Add a share
	share, err := proto.Sign(ctx, []byte("msg"), 1, nil, nil)
	require.NoError(t, err)
	proto.AddShare(share)
	require.Equal(t, 1, proto.BLSShareCount())

	// Clear
	proto.ClearShares()
	require.Equal(t, 0, proto.BLSShareCount())
	require.False(t, proto.CanFinalize())
}

func TestQuasarGroupKeyBytes(t *testing.T) {
	ctx := context.Background()

	parties := []party.ID{party.ID("a"), party.ID("b"), party.ID("c")}

	dealer := &quasar.TrustedDealer{
		Threshold:    2,
		TotalParties: 3,
	}

	_, groupKey, err := dealer.GenerateShares(ctx, parties)
	require.NoError(t, err)

	bytes := groupKey.Bytes()
	require.NotEmpty(t, bytes)
}

func TestQuasarVerifyNilInputs(t *testing.T) {
	// Nil signature
	valid, err := quasar.Verify(&quasar.GroupKey{}, []byte("msg"), nil)
	require.Error(t, err)
	require.False(t, valid)

	// Nil group key
	valid, err = quasar.Verify(nil, []byte("msg"), &quasar.Signature{})
	require.Error(t, err)
	require.False(t, valid)

	// BLS-only verification with nil
	require.False(t, quasar.VerifyBLSOnly(nil, []byte("msg"), nil))
	require.False(t, quasar.VerifyCoronaOnly(nil, "msg", nil))
}
