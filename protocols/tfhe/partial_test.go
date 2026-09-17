// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package tfhe

import (
	"testing"

	"github.com/luxfi/fhe"
	"github.com/luxfi/lattice/v7/utils/sampling"
)

// TestKernel verifies that the canonical 2-of-3
// flow recovers the plaintext bit. This is the smoke test: real shares,
// real partials, real Lagrange combine, real bit decoding.
func TestKernel(t *testing.T) {
	for _, value := range []bool{false, true} {
		kernelRoundTrip(t, fhe.PN10QP27, 2, 3, value)
	}
}

// TestWide covers an asymmetric setup. Uses
// PN11QP54 because PN10QP27's modulus is too small to support t=5 with
// secure noise flooding (Λ_max · σ · √t · 6 > Q/16 at PN10).
func TestWide(t *testing.T) {
	for _, value := range []bool{false, true} {
		kernelRoundTrip(t, fhe.PN11QP54, 5, 9, value)
	}
}

// TestLarge covers a larger committee at PN11QP54.
func TestLarge(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 11-of-21 round-trip under -short")
	}
	for _, value := range []bool{false, true} {
		kernelRoundTrip(t, fhe.PN11QP54, 11, 21, value)
	}
}

func kernelRoundTrip(t *testing.T, lit fhe.ParametersLiteral, threshold, total int, value bool) {
	t.Helper()
	params, err := fhe.NewParametersFromLiteral(lit)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	kgen := fhe.NewKeyGenerator(params)
	sk, _ := kgen.GenKeyPair()

	// Distribute shares.
	shares, err := Split(sk, params, threshold, total)
	if err != nil {
		t.Fatalf("share: %v", err)
	}
	if got, want := len(shares), total; got != want {
		t.Fatalf("share count: got %d want %d", got, want)
	}

	// Encrypt with the master key (collective public key in the
	// production flow; either yields the same threshold-decryptable
	// ciphertext).
	enc := fhe.NewEncryptor(params, sk)
	ct := enc.Encrypt(value)

	// Each party in a chosen subset of size `threshold` produces a
	// partial. We choose the *last* t parties to avoid lucky alignment
	// with the first-t shares carrying obviously-small Lagrange weights.
	subset := shares[total-threshold:]
	partials := make([]*Partial, threshold)
	for i, share := range subset {
		share := share
		prng, err := sampling.NewPRNG()
		if err != nil {
			t.Fatalf("prng: %v", err)
		}
		p, err := share.Partial(ct, params, threshold, prng)
		if err != nil {
			t.Fatalf("partial[%d]: %v", i, err)
		}
		if p.Index != share.Index {
			t.Fatalf("partial index mismatch: got %d want %d", p.Index, share.Index)
		}
		partials[i] = p
	}

	got, err := Combine(ct, partials, params)
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	if got != value {
		t.Fatalf("round trip: got %v want %v (subset of %d, threshold %d)", got, value, total, threshold)
	}
}

// TestShort confirms that 1 of 3
// partials cannot recover the plaintext (negative correctness test).
//
// A single partial is c_1*s_0 + e_0, unrelated to the plaintext.
func TestShort(t *testing.T) {
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	kgen := fhe.NewKeyGenerator(params)
	sk, _ := kgen.GenKeyPair()
	shares, err := Split(sk, params, 2, 3)
	if err != nil {
		t.Fatalf("share: %v", err)
	}
	enc := fhe.NewEncryptor(params, sk)
	ct := enc.Encrypt(true)

	prng, _ := sampling.NewPRNG()
	share := shares[0]
	p, err := share.Partial(ct, params, 1, prng)
	if err != nil {
		t.Fatalf("partial: %v", err)
	}

	// With one partial the Lagrange basis is 1, so the result is c_0 + d_0.
	disagreements := 0
	trials := 32
	for i := 0; i < trials; i++ {
		value := i&1 == 0
		ct2 := enc.Encrypt(value)
		prng2, _ := sampling.NewPRNG()
		p2, err := share.Partial(ct2, params, 1, prng2)
		if err != nil {
			t.Fatalf("partial[%d]: %v", i, err)
		}
		got, err := Combine(ct2, []*Partial{p2}, params)
		if err != nil {
			t.Fatalf("combine[%d]: %v", i, err)
		}
		if got != value {
			disagreements++
		}
	}
	_ = p
	if disagreements == 0 {
		t.Fatalf("below-threshold combine should disagree with plaintext; got 0/%d disagreements", trials)
	}
}

// TestSplit verifies that no party's
// stored share equals the master secret key polynomial.
func TestSplit(t *testing.T) {
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	kgen := fhe.NewKeyGenerator(params)
	sk, _ := kgen.GenKeyPair()
	shares, err := Split(sk, params, 2, 3)
	if err != nil {
		t.Fatalf("share: %v", err)
	}

	// Lift sk to standard form to compare against shares (the share
	// representation).
	ringQ := params.ParamsLWE().RingQ()
	skStd := ringQ.NewPoly()
	ringQ.IMForm(sk.SKLWE.Value.Q, skStd)
	ringQ.INTT(skStd, skStd)

	for _, share := range shares {
		for i := 0; i < ringQ.N(); i++ {
			if share.Coeffs[i] == skStd.Coeffs[0][i] && share.Coeffs[i] != 0 {
				// A single coordinate matching is statistically possible.
				// We only flag if the entire vector matches.
			}
		}
		match := true
		for i := 0; i < ringQ.N(); i++ {
			if share.Coeffs[i] != skStd.Coeffs[0][i] {
				match = false
				break
			}
		}
		if match {
			t.Fatalf("share at index %d equals master secret coefficients", share.Index)
		}
	}
}

// TestDuplicate verifies the dedup guard.
func TestDuplicate(t *testing.T) {
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	kgen := fhe.NewKeyGenerator(params)
	sk, _ := kgen.GenKeyPair()
	shares, err := Split(sk, params, 2, 3)
	if err != nil {
		t.Fatalf("share: %v", err)
	}
	enc := fhe.NewEncryptor(params, sk)
	ct := enc.Encrypt(true)
	prng, _ := sampling.NewPRNG()
	share := shares[0]
	p, err := share.Partial(ct, params, 1, prng)
	if err != nil {
		t.Fatalf("partial: %v", err)
	}

	// The same partial twice must error before combining.
	if _, err := combine(ct.Ciphertext, []*Partial{p, p}, params.ParamsLWE()); err == nil {
		t.Fatal("expected duplicate-index error")
	}
}

// TestModulus guards against cross-parameter mixing.
func TestModulus(t *testing.T) {
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	kgen := fhe.NewKeyGenerator(params)
	sk, _ := kgen.GenKeyPair()
	shares, err := Split(sk, params, 2, 3)
	if err != nil {
		t.Fatalf("share: %v", err)
	}
	enc := fhe.NewEncryptor(params, sk)
	ct := enc.Encrypt(true)
	prng, _ := sampling.NewPRNG()
	share := shares[0]
	p, err := share.Partial(ct, params, 1, prng)
	if err != nil {
		t.Fatalf("partial: %v", err)
	}
	p.Q = p.Q ^ 1
	if _, err := combine(ct.Ciphertext, []*Partial{p}, params.ParamsLWE()); err == nil {
		t.Fatal("expected q-mismatch error")
	}
}

// TestDeterminism verifies that
// running the combine on the SAME partials yields the SAME plaintext.
// (PartialDecrypt is non-deterministic due to fresh noise; combine is
// deterministic in its inputs.)
func TestDeterminism(t *testing.T) {
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	kgen := fhe.NewKeyGenerator(params)
	sk, _ := kgen.GenKeyPair()
	shares, err := Split(sk, params, 2, 3)
	if err != nil {
		t.Fatalf("share: %v", err)
	}
	enc := fhe.NewEncryptor(params, sk)
	ct := enc.Encrypt(true)

	prng1, _ := sampling.NewPRNG()
	prng2, _ := sampling.NewPRNG()
	share0 := shares[0]
	share1 := shares[1]
	p0, err := share0.Partial(ct, params, 2, prng1)
	if err != nil {
		t.Fatalf("partial 0: %v", err)
	}
	p1, err := share1.Partial(ct, params, 2, prng2)
	if err != nil {
		t.Fatalf("partial 1: %v", err)
	}

	// Run combine twice on the same partials.
	got1, err := Combine(ct, []*Partial{p0, p1}, params)
	if err != nil {
		t.Fatalf("combine 1: %v", err)
	}
	got2, err := Combine(ct, []*Partial{p0, p1}, params)
	if err != nil {
		t.Fatalf("combine 2: %v", err)
	}
	if got1 != got2 {
		t.Fatalf("combine non-deterministic in inputs: %v vs %v", got1, got2)
	}
	if !got1 {
		t.Fatalf("plaintext recovery failed: got false want true")
	}
}
