// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package tfhe_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/luxfi/fhe"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/tfhe"
)

// makeParties returns N party IDs. Each ID has a distinct byte pattern so
// the derived x-coordinates (party-ID bytes interpreted big-endian mod QLWE)
// are pairwise unique — Lagrange combine requires this.
//
// We deliberately use short numeric strings rather than random hex to keep
// failures readable; collision checks are enforced inside DealRealKeyShares
// so any future ID scheme will fail loudly rather than silently.
func makeParties(n int) []party.ID {
	out := make([]party.ID, n)
	for i := 0; i < n; i++ {
		// Format with leading zero so all IDs share a length (purely
		// cosmetic; x-coords differ in the trailing byte regardless).
		out[i] = party.ID(fmt.Sprintf("p%03d", i+1))
	}
	return out
}

// partialDecryptCase exercises the Phase-1 surface end-to-end:
//
//  1. Deal real M-of-N shares to N parties.
//  2. Encrypt a known bit with the collective public key.
//  3. Every party computes its PartialDecrypt against the ciphertext.
//  4. Pick a subset of `threshold` partials and feed them to CombineShares.
//  5. Assert the recovered bit equals the input bit.
//  6. Optionally: assert the master key is not reachable from any RealKeyShare.
func partialDecryptCase(t *testing.T, total, threshold int) {
	t.Helper()
	ctx := context.Background()

	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	parties := makeParties(total)
	pk, shares, err := tfhe.DealRealKeyShares(ctx, params, threshold, parties)
	if err != nil {
		t.Fatalf("DealRealKeyShares: %v", err)
	}
	if len(shares) != total {
		t.Fatalf("expected %d shares, got %d", total, len(shares))
	}

	// Encrypt with the collective public key.
	enc := fhe.NewBitwisePublicEncryptor(params, pk)

	for _, plainBit := range []bool{false, true} {
		ct, err := enc.Encrypt(plainBit)
		if err != nil {
			t.Fatalf("encrypt bit=%v: %v", plainBit, err)
		}

		// Every party computes its partial. We later use only `threshold`
		// of them but generating all-N exercises the full surface.
		partials := make([]*tfhe.PartialShare, 0, total)
		for _, pid := range parties {
			p, err := shares[pid].PartialDecrypt(ct, nil)
			if err != nil {
				t.Fatalf("PartialDecrypt for %s: %v", pid, err)
			}
			partials = append(partials, p)
		}

		// Use a deterministic subset of the first `threshold` partials.
		subset := partials[:threshold]
		bit, noisy, err := tfhe.CombineShares(params, ct, subset, threshold)
		if err != nil {
			t.Fatalf("CombineShares (T=%d/N=%d, plain=%v): %v", threshold, total, plainBit, err)
		}
		if bit != plainBit {
			t.Fatalf("T=%d/N=%d plain=%v recovered=%v noisy=%v", threshold, total, plainBit, bit, noisy)
		}

		// Subset independence: a *different* authorised subset must recover
		// the same bit. Take the *last* `threshold` partials and re-combine.
		subset2 := partials[total-threshold:]
		bit2, _, err := tfhe.CombineShares(params, ct, subset2, threshold)
		if err != nil {
			t.Fatalf("CombineShares (alt subset): %v", err)
		}
		if bit2 != plainBit {
			t.Fatalf("alt subset recovered=%v expected=%v", bit2, plainBit)
		}
	}
}

func TestPartialDecrypt_5of3(t *testing.T)   { partialDecryptCase(t, 5, 3) }
func TestPartialDecrypt_21of11(t *testing.T) { partialDecryptCase(t, 21, 11) }
func TestPartialDecrypt_3of2(t *testing.T)   { partialDecryptCase(t, 3, 2) }
func TestPartialDecrypt_7of4(t *testing.T)   { partialDecryptCase(t, 7, 4) }

// partialDecryptCaseWithParams parameterises partialDecryptCase over an
// arbitrary FHE parameter set. Used to spot-check the production STD128
// parameter set from issue #20's acceptance criteria.
func partialDecryptCaseWithParams(t *testing.T, lit fhe.ParametersLiteral, total, threshold int) {
	t.Helper()
	ctx := context.Background()

	params, err := fhe.NewParametersFromLiteral(lit)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	parties := makeParties(total)
	pk, shares, err := tfhe.DealRealKeyShares(ctx, params, threshold, parties)
	if err != nil {
		t.Fatalf("DealRealKeyShares: %v", err)
	}

	enc := fhe.NewBitwisePublicEncryptor(params, pk)
	for _, plainBit := range []bool{false, true} {
		ct, err := enc.Encrypt(plainBit)
		if err != nil {
			t.Fatalf("encrypt bit=%v: %v", plainBit, err)
		}

		partials := make([]*tfhe.PartialShare, 0, threshold)
		for i := 0; i < threshold; i++ {
			p, err := shares[parties[i]].PartialDecrypt(ct, nil)
			if err != nil {
				t.Fatalf("PartialDecrypt for %s: %v", parties[i], err)
			}
			partials = append(partials, p)
		}

		bit, _, err := tfhe.CombineShares(params, ct, partials, threshold)
		if err != nil {
			t.Fatalf("CombineShares (T=%d/N=%d, plain=%v): %v", threshold, total, plainBit, err)
		}
		if bit != plainBit {
			t.Fatalf("T=%d/N=%d plain=%v recovered=%v", threshold, total, plainBit, bit)
		}
	}
}

// TestPartialDecrypt_STD128_5of3 spot-checks issue #20's acceptance parameter
// set (PN9QP28_STD128, matching OpenFHE's STD128_LMKCDEY) at N=5/M=3 to
// confirm the Phase-1 implementation is not silently coupled to the dev
// PN10QP27 set. A noise-budget proof for STD128 is deferred to Phase 2 (see
// the package doc + PR body).
func TestPartialDecrypt_STD128_5of3(t *testing.T) {
	partialDecryptCaseWithParams(t, fhe.PN9QP28_STD128, 5, 3)
}

// TestPartialDecrypt_RejectsInsufficient verifies CombineShares refuses to
// reconstruct from fewer than `threshold` partials. This is the security
// boundary: an attacker who has compromised < threshold parties learns
// nothing about the plaintext.
func TestPartialDecrypt_RejectsInsufficient(t *testing.T) {
	ctx := context.Background()
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	total, threshold := 5, 3
	parties := makeParties(total)

	pk, shares, err := tfhe.DealRealKeyShares(ctx, params, threshold, parties)
	if err != nil {
		t.Fatalf("DealRealKeyShares: %v", err)
	}

	enc := fhe.NewBitwisePublicEncryptor(params, pk)
	ct, err := enc.Encrypt(true)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Only `threshold - 1` partials. Must refuse.
	partials := make([]*tfhe.PartialShare, 0, threshold-1)
	for i := 0; i < threshold-1; i++ {
		p, err := shares[parties[i]].PartialDecrypt(ct, nil)
		if err != nil {
			t.Fatalf("PartialDecrypt: %v", err)
		}
		partials = append(partials, p)
	}

	if _, _, err := tfhe.CombineShares(params, ct, partials, threshold); err == nil {
		t.Fatal("expected error for sub-threshold partial count, got nil")
	}
}

// TestPartialDecrypt_BindingHashRejectsMisroute confirms that partials
// produced against ciphertext A cannot be combined with partials produced
// against ciphertext B — a cross-ciphertext mix-and-match attack must fail.
func TestPartialDecrypt_BindingHashRejectsMisroute(t *testing.T) {
	ctx := context.Background()
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	total, threshold := 5, 3
	parties := makeParties(total)

	pk, shares, err := tfhe.DealRealKeyShares(ctx, params, threshold, parties)
	if err != nil {
		t.Fatalf("DealRealKeyShares: %v", err)
	}

	enc := fhe.NewBitwisePublicEncryptor(params, pk)
	ctA, err := enc.Encrypt(true)
	if err != nil {
		t.Fatalf("encrypt A: %v", err)
	}
	ctB, err := enc.Encrypt(false)
	if err != nil {
		t.Fatalf("encrypt B: %v", err)
	}

	pA1, err := shares[parties[0]].PartialDecrypt(ctA, nil)
	if err != nil {
		t.Fatal(err)
	}
	pA2, err := shares[parties[1]].PartialDecrypt(ctA, nil)
	if err != nil {
		t.Fatal(err)
	}
	pB3, err := shares[parties[2]].PartialDecrypt(ctB, nil)
	if err != nil {
		t.Fatal(err)
	}

	mixed := []*tfhe.PartialShare{pA1, pA2, pB3}
	if _, _, err := tfhe.CombineShares(params, ctA, mixed, threshold); err == nil {
		t.Fatal("expected error for mixed-ciphertext partials, got nil")
	}
}

// TestPartialDecrypt_MasterKeyNotMaterialisedOnParty checks the structural
// invariant from the issue: no RealKeyShare carries the master secret key.
// A RealKeyShare only contains a per-party SKLWEShareNTT polynomial whose
// coefficients are Shamir shares of the master coefficients; the master
// polynomial itself is never present in the returned share.
//
// This is a structural test, not a cryptographic one — it checks the struct
// shape, not statistical indistinguishability — but it catches the most
// obvious regression: someone wires `UnderlyingKey: masterSK` back into the
// share (as the legacy fake path did).
func TestPartialDecrypt_MasterKeyNotMaterialisedOnParty(t *testing.T) {
	ctx := context.Background()
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	parties := makeParties(5)
	_, shares, err := tfhe.DealRealKeyShares(ctx, params, 3, parties)
	if err != nil {
		t.Fatalf("DealRealKeyShares: %v", err)
	}

	// Each party's share polynomial must NOT equal any other party's share
	// polynomial — if they did, the dealer would have given everyone the
	// same (i.e. full) key, defeating the threshold property.
	seen := make(map[uint64]party.ID)
	for pid, s := range shares {
		if s.SKLWEShareNTT.N() != params.N() {
			t.Errorf("share for %s has wrong ring degree %d (want %d)", pid, s.SKLWEShareNTT.N(), params.N())
		}
		head := s.SKLWEShareNTT.Coeffs[0][0]
		if prev, dup := seen[head]; dup {
			t.Fatalf("two parties (%s, %s) have identical first share coefficient — suggests every party got the same key (master-key replication regression)", prev, pid)
		}
		seen[head] = pid
	}
}
