// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls_test

// Integration test for luxfi/crypto/signer's threshold-signing feature
// backed by the BLS Scheme. It lives HERE (not in luxfi/crypto) because it
// needs a concrete threshold scheme: importing crypto/signer from
// luxfi/threshold is the allowed dependency direction (threshold -> crypto),
// whereas the reverse would create a crypto <-> threshold module cycle.

import (
	"context"
	"testing"

	"github.com/luxfi/crypto/signer"
	"github.com/luxfi/crypto/threshold"
	bls "github.com/luxfi/threshold/scheme/bls" // BLS Scheme (init registers it) + RunDKG
)

func TestSignerWithThresholdBLS(t *testing.T) {
	// BLS Scheme must be registered (the bls import's init did this).
	if _, err := threshold.GetScheme(threshold.SchemeBLS); err != nil {
		t.Fatalf("GetScheme(BLS): %v", err)
	}

	// Dealerless keygen: Pedersen-VSS DKG, no trusted dealer.
	shares, groupKey, err := bls.RunDKG(context.Background(), 2, 3, nil)
	if err != nil {
		t.Fatalf("RunDKG: %v", err)
	}

	signers := make([]*signer.Signer, len(shares))
	for i, share := range shares {
		s, err := signer.NewSignerWithThreshold(share)
		if err != nil {
			t.Fatalf("NewSignerWithThreshold[%d]: %v", i, err)
		}
		signers[i] = s
	}

	t.Run("KeyInfo", func(t *testing.T) {
		for i, s := range signers {
			if !s.HasThresholdKey() {
				t.Fatalf("signer %d missing threshold key", i)
			}
			if s.ThresholdSchemeID() != threshold.SchemeBLS {
				t.Fatalf("signer %d: scheme %v, want BLS", i, s.ThresholdSchemeID())
			}
			if s.ThresholdIndex() != i {
				t.Fatalf("signer %d: index %d", i, s.ThresholdIndex())
			}
			if !s.ThresholdGroupKey().Equal(groupKey) {
				t.Fatalf("signer %d: group key mismatch", i)
			}
		}
	})

	t.Run("SetThresholdKeyShare", func(t *testing.T) {
		s, err := signer.NewSigner()
		if err != nil {
			t.Fatal(err)
		}
		if s.HasThresholdKey() {
			t.Fatal("fresh signer should have no threshold key")
		}
		if err := s.SetThresholdKeyShare(shares[0]); err != nil {
			t.Fatalf("SetThresholdKeyShare: %v", err)
		}
		if !s.HasThresholdKey() || s.ThresholdIndex() != 0 {
			t.Fatal("threshold key not set correctly")
		}
	})
}
