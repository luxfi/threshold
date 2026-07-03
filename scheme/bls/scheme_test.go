// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls

import (
	"context"
	"testing"

	"github.com/luxfi/crypto/threshold"
)

func TestSchemeRegistration(t *testing.T) {
	// Verify scheme is registered via init()
	if !threshold.HasScheme(threshold.SchemeBLS) {
		t.Fatal("BLS scheme not registered")
	}

	scheme, err := threshold.GetScheme(threshold.SchemeBLS)
	if err != nil {
		t.Fatalf("GetScheme failed: %v", err)
	}

	if scheme.ID() != threshold.SchemeBLS {
		t.Errorf("scheme ID = %v, want %v", scheme.ID(), threshold.SchemeBLS)
	}

	if scheme.Name() != "BLS Threshold" {
		t.Errorf("scheme Name = %v, want %v", scheme.Name(), "BLS Threshold")
	}
}

func TestSchemeConstants(t *testing.T) {
	scheme := &Scheme{}

	if scheme.KeyShareSize() != KeyShareSize {
		t.Errorf("KeyShareSize = %d, want %d", scheme.KeyShareSize(), KeyShareSize)
	}

	if scheme.SignatureShareSize() != SignatureShareSize {
		t.Errorf("SignatureShareSize = %d, want %d", scheme.SignatureShareSize(), SignatureShareSize)
	}

	if scheme.SignatureSize() != SignatureSize {
		t.Errorf("SignatureSize = %d, want %d", scheme.SignatureSize(), SignatureSize)
	}

	if scheme.PublicKeySize() != PublicKeySize {
		t.Errorf("PublicKeySize = %d, want %d", scheme.PublicKeySize(), PublicKeySize)
	}
}

func TestTrustedDealerKeyGeneration(t *testing.T) {
	scheme := &Scheme{}

	config := threshold.DealerConfig{
		Threshold:    2, // 3-of-5 threshold
		TotalParties: 5,
	}

	dealer, err := scheme.NewTrustedDealer(config)
	if err != nil {
		t.Fatalf("NewTrustedDealer failed: %v", err)
	}

	ctx := context.Background()
	shares, groupKey, err := dealer.GenerateShares(ctx)
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	// Verify correct number of shares
	if len(shares) != config.TotalParties {
		t.Errorf("got %d shares, want %d", len(shares), config.TotalParties)
	}

	// Verify each share
	for i, share := range shares {
		if share.Index() != i {
			t.Errorf("share %d has index %d", i, share.Index())
		}

		if share.Threshold() != config.Threshold {
			t.Errorf("share %d threshold = %d, want %d", i, share.Threshold(), config.Threshold)
		}

		if share.TotalParties() != config.TotalParties {
			t.Errorf("share %d totalParties = %d, want %d", i, share.TotalParties(), config.TotalParties)
		}

		if share.SchemeID() != threshold.SchemeBLS {
			t.Errorf("share %d schemeID = %v, want %v", i, share.SchemeID(), threshold.SchemeBLS)
		}

		// Verify group key matches
		if !share.GroupKey().Equal(groupKey) {
			t.Errorf("share %d group key mismatch", i)
		}
	}

	// Verify group key
	if groupKey == nil {
		t.Fatal("groupKey is nil")
	}

	if groupKey.SchemeID() != threshold.SchemeBLS {
		t.Errorf("groupKey schemeID = %v, want %v", groupKey.SchemeID(), threshold.SchemeBLS)
	}
}

func TestKeyShareSerialization(t *testing.T) {
	scheme := &Scheme{}

	config := threshold.DealerConfig{
		Threshold:    1,
		TotalParties: 3,
	}

	dealer, err := scheme.NewTrustedDealer(config)
	if err != nil {
		t.Fatalf("NewTrustedDealer failed: %v", err)
	}

	ctx := context.Background()
	shares, _, err := dealer.GenerateShares(ctx)
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	// Test serialization/deserialization
	for i, share := range shares {
		data := share.Bytes()
		if len(data) != KeyShareSize {
			t.Errorf("share %d bytes length = %d, want %d", i, len(data), KeyShareSize)
		}

		parsed, err := scheme.ParseKeyShare(data)
		if err != nil {
			t.Errorf("ParseKeyShare failed for share %d: %v", i, err)
			continue
		}

		if parsed.Index() != share.Index() {
			t.Errorf("parsed index = %d, want %d", parsed.Index(), share.Index())
		}

		if parsed.Threshold() != share.Threshold() {
			t.Errorf("parsed threshold = %d, want %d", parsed.Threshold(), share.Threshold())
		}
	}
}

func TestSignerCreation(t *testing.T) {
	scheme := &Scheme{}

	config := threshold.DealerConfig{
		Threshold:    1,
		TotalParties: 3,
	}

	dealer, err := scheme.NewTrustedDealer(config)
	if err != nil {
		t.Fatalf("NewTrustedDealer failed: %v", err)
	}

	ctx := context.Background()
	shares, _, err := dealer.GenerateShares(ctx)
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	// Create signers from shares
	for i, share := range shares {
		signer, err := scheme.NewSigner(share)
		if err != nil {
			t.Errorf("NewSigner failed for share %d: %v", i, err)
			continue
		}

		if signer.Index() != i {
			t.Errorf("signer index = %d, want %d", signer.Index(), i)
		}

		// Verify public share is not empty
		pubShare := signer.PublicShare()
		if len(pubShare) == 0 {
			t.Errorf("signer %d has empty public share", i)
		}
	}
}

func TestSigningAndAggregation(t *testing.T) {
	scheme := &Scheme{}

	config := threshold.DealerConfig{
		Threshold:    1, // 2-of-3 threshold
		TotalParties: 3,
	}

	dealer, err := scheme.NewTrustedDealer(config)
	if err != nil {
		t.Fatalf("NewTrustedDealer failed: %v", err)
	}

	ctx := context.Background()
	shares, groupKey, err := dealer.GenerateShares(ctx)
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	// Create signers
	signers := make([]threshold.Signer, len(shares))
	for i, share := range shares {
		signer, err := scheme.NewSigner(share)
		if err != nil {
			t.Fatalf("NewSigner failed: %v", err)
		}
		signers[i] = signer
	}

	// Create aggregator
	aggregator, err := scheme.NewAggregator(groupKey)
	if err != nil {
		t.Fatalf("NewAggregator failed: %v", err)
	}

	// Sign a message with first 2 signers (threshold+1)
	message := []byte("test message for threshold signing")
	participantIndices := []int{0, 1}

	signatureShares := make([]threshold.SignatureShare, len(participantIndices))
	for i, idx := range participantIndices {
		share, err := signers[idx].SignShare(ctx, message, participantIndices, nil)
		if err != nil {
			t.Fatalf("SignShare failed for signer %d: %v", idx, err)
		}
		signatureShares[i] = share
	}

	// Verify individual shares
	for i, idx := range participantIndices {
		err := aggregator.VerifyShare(message, signatureShares[i], signers[idx].PublicShare())
		if err != nil {
			t.Errorf("VerifyShare failed for signer %d: %v", idx, err)
		}
	}

	// Aggregate shares
	signature, err := aggregator.Aggregate(ctx, message, signatureShares, nil)
	if err != nil {
		t.Fatalf("Aggregate failed: %v", err)
	}

	// Verify signature is not nil
	if signature == nil {
		t.Fatal("signature is nil")
	}

	// Verify scheme ID
	if signature.SchemeID() != threshold.SchemeBLS {
		t.Errorf("signature schemeID = %v, want %v", signature.SchemeID(), threshold.SchemeBLS)
	}
}

func TestVerifier(t *testing.T) {
	scheme := &Scheme{}

	config := threshold.DealerConfig{
		Threshold:    1,
		TotalParties: 3,
	}

	dealer, err := scheme.NewTrustedDealer(config)
	if err != nil {
		t.Fatalf("NewTrustedDealer failed: %v", err)
	}

	ctx := context.Background()
	shares, groupKey, err := dealer.GenerateShares(ctx)
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	// Create verifier
	verifier, err := scheme.NewVerifier(groupKey)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	// Verify group key matches
	if !verifier.GroupKey().Equal(groupKey) {
		t.Error("verifier group key mismatch")
	}

	// Create a signer and sign
	signer, err := scheme.NewSigner(shares[0])
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	message := []byte("test message")
	share, err := signer.SignShare(ctx, message, []int{0}, nil)
	if err != nil {
		t.Fatalf("SignShare failed: %v", err)
	}

	// Create aggregator and aggregate (single share for test)
	aggregator, err := scheme.NewAggregator(groupKey)
	if err != nil {
		t.Fatalf("NewAggregator failed: %v", err)
	}

	sig, err := aggregator.Aggregate(ctx, message, []threshold.SignatureShare{share}, nil)
	if err != nil {
		t.Fatalf("Aggregate failed: %v", err)
	}

	// Verify the signature
	if !verifier.Verify(message, sig) {
		t.Error("Verify returned false, expected true")
	}

	// Verify with bytes
	if !verifier.VerifyBytes(message, sig.Bytes()) {
		t.Error("VerifyBytes returned false, expected true")
	}

	// Verify wrong message fails
	if verifier.Verify([]byte("wrong message"), sig) {
		t.Error("Verify returned true for wrong message, expected false")
	}
}

func TestDKGConfig(t *testing.T) {
	scheme := &Scheme{}

	// NewDKG is intentionally unimplemented — it must return an error
	// directing callers to threshold/protocols/frost for production DKG.
	config := threshold.DKGConfig{
		Threshold:    1,
		TotalParties: 3,
		PartyIndex:   0,
	}

	_, err := scheme.NewDKG(config)
	if err == nil {
		t.Fatal("NewDKG should return an error (not implemented)")
	}
}

func TestSignatureShareSerialization(t *testing.T) {
	scheme := &Scheme{}

	config := threshold.DealerConfig{
		Threshold:    1,
		TotalParties: 3,
	}

	dealer, err := scheme.NewTrustedDealer(config)
	if err != nil {
		t.Fatalf("NewTrustedDealer failed: %v", err)
	}

	ctx := context.Background()
	shares, _, err := dealer.GenerateShares(ctx)
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	signer, err := scheme.NewSigner(shares[0])
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	message := []byte("test message")
	sigShare, err := signer.SignShare(ctx, message, []int{0}, nil)
	if err != nil {
		t.Fatalf("SignShare failed: %v", err)
	}

	// Serialize
	data := sigShare.Bytes()
	if len(data) != SignatureShareSize {
		t.Errorf("signature share bytes length = %d, want %d", len(data), SignatureShareSize)
	}

	// Deserialize
	parsed, err := scheme.ParseSignatureShare(data)
	if err != nil {
		t.Fatalf("ParseSignatureShare failed: %v", err)
	}

	if parsed.Index() != sigShare.Index() {
		t.Errorf("parsed index = %d, want %d", parsed.Index(), sigShare.Index())
	}

	if parsed.SchemeID() != threshold.SchemeBLS {
		t.Errorf("parsed schemeID = %v, want %v", parsed.SchemeID(), threshold.SchemeBLS)
	}
}

func TestPublicKeySerialization(t *testing.T) {
	scheme := &Scheme{}

	config := threshold.DealerConfig{
		Threshold:    1,
		TotalParties: 3,
	}

	dealer, err := scheme.NewTrustedDealer(config)
	if err != nil {
		t.Fatalf("NewTrustedDealer failed: %v", err)
	}

	ctx := context.Background()
	_, groupKey, err := dealer.GenerateShares(ctx)
	if err != nil {
		t.Fatalf("GenerateShares failed: %v", err)
	}

	// Serialize
	data := groupKey.Bytes()
	if len(data) != PublicKeySize {
		t.Errorf("public key bytes length = %d, want %d", len(data), PublicKeySize)
	}

	// Deserialize
	parsed, err := scheme.ParsePublicKey(data)
	if err != nil {
		t.Fatalf("ParsePublicKey failed: %v", err)
	}

	if !parsed.Equal(groupKey) {
		t.Error("parsed public key does not equal original")
	}

	if parsed.SchemeID() != threshold.SchemeBLS {
		t.Errorf("parsed schemeID = %v, want %v", parsed.SchemeID(), threshold.SchemeBLS)
	}
}

func TestPublicKeyEquality(t *testing.T) {
	scheme := &Scheme{}

	config := threshold.DealerConfig{
		Threshold:    1,
		TotalParties: 3,
	}

	dealer, err := scheme.NewTrustedDealer(config)
	if err != nil {
		t.Fatalf("NewTrustedDealer failed: %v", err)
	}

	ctx := context.Background()

	// Generate two different group keys
	_, groupKey1, err := dealer.GenerateShares(ctx)
	if err != nil {
		t.Fatalf("GenerateShares 1 failed: %v", err)
	}

	_, groupKey2, err := dealer.GenerateShares(ctx)
	if err != nil {
		t.Fatalf("GenerateShares 2 failed: %v", err)
	}

	// Same key should be equal to itself
	if !groupKey1.Equal(groupKey1) {
		t.Error("group key should equal itself")
	}

	// Different keys should not be equal (with very high probability)
	// Note: There's an astronomically small chance this could fail randomly
	if groupKey1.Equal(groupKey2) {
		t.Error("different group keys should not be equal")
	}
}
