// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsa

import (
	"reflect"
	"sort"
	"testing"
)

func TestRSSSubsets_Count(t *testing.T) {
	// Subsets of size N-T+1 from [N], counted.
	cases := []struct {
		tt, n, want int
	}{
		{2, 2, 2},  // C(2,1) = 2
		{2, 3, 3},  // C(3,2) = 3
		{3, 3, 3},  // C(3,1) = 3
		{3, 5, 10}, // C(5,3) = 10
		{4, 6, 20}, // C(6,3) = 20
		{6, 6, 6},  // C(6,1) = 6
	}
	for _, c := range cases {
		got := RSSSubsets(c.tt, c.n)
		if len(got) != c.want {
			t.Errorf("RSSSubsets(T=%d,N=%d): got %d subsets, want %d",
				c.tt, c.n, len(got), c.want)
		}
	}
}

func TestRecover_TNCoversAllSecrets(t *testing.T) {
	// For every supported (T, N), the recovery partition must cover every RSS
	// subset exactly once across the active parties.
	for n := 2; n <= 6; n++ {
		for tt := 2; tt <= n; tt++ {
			act := make([]int, tt)
			for i := range act {
				act[i] = i
			}
			rec := Recover(act, n)
			seen := map[string]int{}
			for _, shares := range rec {
				for _, sh := range shares {
					sort.Ints(sh)
					key := shareKey(sh)
					seen[key]++
				}
			}
			subs := RSSSubsets(tt, n)
			for _, s := range subs {
				sort.Ints(s)
				c := seen[shareKey(s)]
				if c != 1 {
					t.Errorf("T=%d N=%d: subset %v covered %d times, want 1",
						tt, n, []int(s), c)
				}
			}
		}
	}
}

func TestRecover_TEqualsN(t *testing.T) {
	// When T=N the only subsets are singletons; each party gets exactly one.
	for n := 2; n <= 6; n++ {
		act := make([]int, n)
		for i := range act {
			act[i] = i
		}
		rec := Recover(act, n)
		for p, shares := range rec {
			if len(shares) != 1 {
				t.Errorf("T=N=%d party %d: got %d shares, want 1", n, p, len(shares))
			}
			if len(shares[0]) != 1 || shares[0][0] != p {
				t.Errorf("T=N=%d party %d: got share %v, want {%d}", n, p, []int(shares[0]), p)
			}
		}
	}
}

func TestRecover_BalanceBound(t *testing.T) {
	// Appendix B: each party uses at most ⌈C(N, N-T+1) / T⌉ secrets.
	for n := 2; n <= 6; n++ {
		for tt := 2; tt < n; tt++ {
			act := make([]int, tt)
			for i := range act {
				act[i] = i
			}
			total := len(RSSSubsets(tt, n))
			bound := (total + tt - 1) / tt // ceiling
			rec := Recover(act, n)
			for _, shares := range rec {
				if len(shares) > bound {
					t.Errorf("T=%d N=%d: party had %d shares, bound %d",
						tt, n, len(shares), bound)
				}
			}
		}
	}
}

func TestParams_Coverage(t *testing.T) {
	// Every (level, T, N) in the valid range must have a parameter entry.
	for _, lvl := range []SecurityLevel{LevelI, LevelIII, LevelV} {
		for n := 2; n <= 6; n++ {
			for tt := 2; tt <= n; tt++ {
				if _, ok := Params(lvl, tt, n); !ok {
					t.Errorf("missing params for level=%d T=%d N=%d", lvl, tt, n)
				}
			}
		}
	}
}

func TestParams_OutOfRange(t *testing.T) {
	for _, bad := range [][2]int{{1, 2}, {3, 2}, {2, 7}, {0, 0}} {
		if _, ok := Params(LevelI, bad[0], bad[1]); ok {
			t.Errorf("expected out-of-range for T=%d N=%d", bad[0], bad[1])
		}
	}
}

func shareKey(s Share) string {
	ints := make([]int, len(s))
	copy(ints, s)
	return intsToKey(ints)
}

func intsToKey(a []int) string {
	b := make([]byte, 0, len(a))
	for _, v := range a {
		b = append(b, byte('0'+v))
	}
	return string(b)
}

// Sanity: Share compares correctly.
var _ = reflect.DeepEqual
