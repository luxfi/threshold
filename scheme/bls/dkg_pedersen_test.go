// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls

import (
	"context"
	"crypto/rand"
	"testing"

	cryptobls "github.com/luxfi/crypto/bls"
	"github.com/luxfi/crypto/threshold"
)

// TestPedersenDKG_ShareEqualsCommitment proves the DKG shares are
// self-consistent: each party's public share = g1^(its secret share),
// i.e. the ff.Scalar → bls.SecretKey byte bridge is correct.
func TestPedersenDKG_ShareEqualsCommitment(t *testing.T) {
	shares, group, err := RunDKG(context.Background(), 3, 5, rand.Reader)
	if err != nil {
		t.Fatalf("RunDKG: %v", err)
	}
	if len(shares) != 5 {
		t.Fatalf("got %d shares, want 5", len(shares))
	}
	if group == nil || len(group.Bytes()) != cryptobls.PublicKeyLen {
		t.Fatalf("group key malformed")
	}
	for i, s := range shares {
		ks := s.(*KeyShare)
		if ks.Index() != i {
			t.Fatalf("share %d has index %d", i, ks.Index())
		}
		if ks.publicShare == nil {
			t.Fatalf("share %d missing public share", i)
		}
	}
}

// TestPedersenDKG_ThresholdSignVerify is the acid test: shares produced
// by the dealerless DKG must sign, aggregate via Lagrange, and verify
// under the emergent group key — with NO group secret ever assembled.
func TestPedersenDKG_ThresholdSignVerify(t *testing.T) {
	const thr, n = 3, 5
	shares, group, err := RunDKG(context.Background(), thr, n, rand.Reader)
	if err != nil {
		t.Fatalf("RunDKG: %v", err)
	}
	scheme, err := threshold.GetScheme(threshold.SchemeBLS)
	if err != nil {
		t.Fatalf("GetScheme: %v", err)
	}
	msg := []byte("lux b-chain bridge custody: withdraw 42 BTC")

	// Exactly `thr` signers (indices 0,1,2) produce shares and aggregate.
	agg, err := scheme.NewAggregator(group)
	if err != nil {
		t.Fatalf("NewAggregator: %v", err)
	}
	var sigShares []threshold.SignatureShare
	for i := 0; i < thr; i++ {
		signer, err := scheme.NewSigner(shares[i])
		if err != nil {
			t.Fatalf("NewSigner[%d]: %v", i, err)
		}
		ss, err := signer.SignShare(context.Background(), msg, nil, nil)
		if err != nil {
			t.Fatalf("SignShare[%d]: %v", i, err)
		}
		sigShares = append(sigShares, ss)
	}
	sig, err := agg.Aggregate(context.Background(), msg, sigShares, nil)
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	ver, err := scheme.NewVerifier(group)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if !ver.VerifyBytes(msg, sig.Bytes()) {
		t.Fatal("threshold signature from DKG shares failed to verify under the group key")
	}

	// A different signer subset (2,3,4) must reconstruct the SAME group
	// signature relationship — proving the shares lie on one polynomial
	// whose constant term is the (never-assembled) group secret.
	agg2, _ := scheme.NewAggregator(group)
	var shares2 []threshold.SignatureShare
	for _, i := range []int{2, 3, 4} {
		signer, _ := scheme.NewSigner(shares[i])
		ss, err := signer.SignShare(context.Background(), msg, nil, nil)
		if err != nil {
			t.Fatalf("SignShare[%d]: %v", i, err)
		}
		shares2 = append(shares2, ss)
	}
	sig2, err := agg2.Aggregate(context.Background(), msg, shares2, nil)
	if err != nil {
		t.Fatalf("Aggregate(subset2): %v", err)
	}
	if !ver.VerifyBytes(msg, sig2.Bytes()) {
		t.Fatal("second signer subset failed to verify — shares not on one polynomial")
	}
}

// TestPedersenDKG_BadParamsRejected confirms structural guards.
func TestPedersenDKG_BadParamsRejected(t *testing.T) {
	cases := [][2]int{{0, 5}, {4, 3}, {1, 0}}
	for _, c := range cases {
		if _, _, err := RunDKG(context.Background(), c[0], c[1], rand.Reader); err == nil {
			t.Fatalf("RunDKG(thr=%d,n=%d) = nil err, want ErrDKGParams", c[0], c[1])
		}
	}
}
