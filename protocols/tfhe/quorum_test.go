// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Which quorums recombine exactly, and that the others are refused rather
// than answered wrongly.

package tfhe

import (
	"strings"
	"testing"

	"github.com/luxfi/fhe"
)

// subsets returns every k-subset of [0,n), as index slices.
func subsets(n, k int) [][]int {
	var out [][]int
	cur := make([]int, 0, k)
	var rec func(start int)
	rec = func(start int) {
		if len(cur) == k {
			out = append(out, append([]int(nil), cur...))
			return
		}
		for i := start; i < n; i++ {
			cur = append(cur, i)
			rec(i + 1)
			cur = cur[:len(cur)-1]
		}
	}
	rec(0)
	return out
}

// TestQuorate pins the predicate. Positions {1,3}
// give λ = {-3/2, 1/2}; {1,2} give {2,-1}.
func TestQuorate(t *testing.T) {
	cases := []struct {
		positions []int
		want      bool
	}{
		{[]int{1, 2}, true},
		{[]int{2, 3}, true},
		{[]int{3, 4}, true},
		{[]int{1, 3}, false},
		{[]int{1, 4}, false},
		{[]int{2, 4}, true},
		{[]int{1, 2, 3}, true},
		{[]int{3, 4, 5}, true},
		{[]int{1, 3, 5}, false},
		{[]int{1, 2, 4}, false},
		{[]int{2, 3, 4}, true},
	}
	for _, c := range cases {
		if got := Quorate(c.positions); got != c.want {
			t.Errorf("Quorate(%v) = %v, want %v", c.positions, got, c.want)
		}
	}
}

// TestLargest checks the quorum of
// largest positions recombines exactly for every size and threshold in range.
func TestLargest(t *testing.T) {
	for total := 1; total <= 24; total++ {
		for thr := 1; thr <= total; thr++ {
			positions := make([]int, 0, thr)
			for p := total - thr + 1; p <= total; p++ {
				positions = append(positions, p)
			}
			if !Quorate(positions) {
				t.Errorf("top quorum %v of %d does not recombine exactly", positions, total)
			}
		}
	}
}

// TestQuorum checks every quorum of threshold
// size either returns the encrypted value or an error, never another value.
func TestQuorum(t *testing.T) {
	for _, c := range []struct{ thr, total int }{{2, 3}, {3, 5}} {
		members, params := newCommittee(t, c.thr, c.total)
		pub, err := members[0].Collective()
		if err != nil {
			t.Fatalf("collective public key: %v", err)
		}

		refused, answered := 0, 0
		for _, sub := range subsets(c.total, c.thr) {
			pick := make([]*Member, 0, c.thr)
			positions := make([]int, 0, c.thr)
			for _, i := range sub {
				pick = append(pick, members[i])
				positions = append(positions, members[i].Share.Index)
			}
			for _, want := range []uint64{0, 1} {
				ciphertext, err := Encrypt(params, pub, want, fhe.FheBool)
				if err != nil {
					t.Fatalf("encrypt: %v", err)
				}
				bits, err := Decrypt(ciphertext, contributions(t, pick, ciphertext), params, c.thr)
				if err != nil {
					refused++
					if Quorate(positions) {
						t.Errorf("%d-of-%d quorum %v recombines exactly but was refused: %v",
							c.thr, c.total, positions, err)
					}
					continue
				}
				answered++
				if !Quorate(positions) {
					t.Errorf("%d-of-%d quorum %v does not recombine exactly but was answered",
						c.thr, c.total, positions)
				}
				if got := Value(bits); got != want {
					t.Fatalf("%d-of-%d quorum %v returned %#x, want %#x",
						c.thr, c.total, positions, got, want)
				}
			}
		}
		if answered == 0 {
			t.Fatalf("%d-of-%d: no quorum decrypted at all", c.thr, c.total)
		}
		if c.total > c.thr && refused == 0 {
			t.Logf("%d-of-%d: every quorum recombined exactly (%d answered)", c.thr, c.total, answered)
		}
	}
}

// TestSearch checks decryption succeeds given every
// member's contribution, where half the quorums of that size cannot
// recombine.
func TestSearch(t *testing.T) {
	members, params := newCommittee(t, 3, 5)
	pub, err := members[0].Collective()
	if err != nil {
		t.Fatalf("collective public key: %v", err)
	}
	for _, want := range []uint64{0x00, 0x01, 0x5A, 0xFF} {
		ciphertext, err := Encrypt(params, pub, want, fhe.FheUint8)
		if err != nil {
			t.Fatalf("encrypt %#x: %v", want, err)
		}
		bits, err := Decrypt(ciphertext, contributions(t, members, ciphertext), params, 3)
		if err != nil {
			t.Fatalf("decrypt %#x with all five contributions: %v", want, err)
		}
		if got := Value(bits); got != want {
			t.Fatalf("recovered %#x, want %#x", got, want)
		}
	}
}

// TestRefusal checks the refusal names its reason,
// distinct from "not enough members".
func TestRefusal(t *testing.T) {
	members, params := newCommittee(t, 2, 3)
	pub, err := members[0].Collective()
	if err != nil {
		t.Fatalf("collective public key: %v", err)
	}
	ciphertext, err := Encrypt(params, pub, 1, fhe.FheBool)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Positions {1,3}: λ = {-3/2, 1/2}.
	bad := []*Member{members[0], members[2]}
	if Quorate([]int{1, 3}) {
		t.Fatal("positions {1,3} unexpectedly recombine exactly; pick another quorum for this test")
	}
	_, err = Decrypt(ciphertext, contributions(t, bad, ciphertext), params, 2)
	if err == nil {
		t.Fatal("Decrypt answered with a quorum that cannot recombine exactly")
	}
	if !strings.Contains(err.Error(), "recombines exactly") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}
