// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsa

import "sort"

// Share identifies a subset I ⊂ [N] with |I| = N-T+1. The RSS scheme produces
// one secret s_I per such subset, known only to parties in I.
type Share []int

// RSSSubsets enumerates all subsets of [N] of size N-T+1 in lexicographic
// order. For each subset I, the RSS scheme samples one s_I ← χ_s and sends it
// to every party in I.
func RSSSubsets(t, n int) []Share {
	k := n - t + 1
	if k <= 0 || k > n {
		return nil
	}
	var out []Share
	var walk func(start int, acc []int)
	walk = func(start int, acc []int) {
		if len(acc) == k {
			s := make(Share, k)
			copy(s, acc)
			out = append(out, s)
			return
		}
		for i := start; i < n; i++ {
			walk(i+1, append(acc, i))
		}
	}
	walk(0, nil)
	return out
}

// Recover computes, for an active signing set act of size T, the partition
// (m_i)_{i∈act} of the RSS subsets such that each secret s_I is assigned to
// exactly one party in act and max_i |m_i| is minimized.
//
// For 2 ≤ T < N ≤ 6 the optimal partitions are hardcoded (Appendix B of the
// paper, Algorithm 6). For T = N each party holds exactly one secret.
func Recover(act []int, n int) map[int][]Share {
	if len(act) == 0 {
		return nil
	}
	sorted := make([]int, len(act))
	copy(sorted, act)
	sort.Ints(sorted)
	t := len(sorted)

	result := make(map[int][]Share)

	// T == N: each party holds exactly one secret (the one with |I| = 1).
	// The only subsets of size N-T+1 = 1 are singletons.
	if t == n {
		for _, p := range sorted {
			result[p] = []Share{{p}}
		}
		return result
	}

	// For small (T, N) use the hardcoded optimal partition for
	// act = {0, 1, ..., T-1} and translate by symmetry.
	tmpl, ok := recoverTemplates[[2]int{t, n}]
	if !ok {
		return fallbackRecover(sorted, n, t)
	}

	// Build a permutation φ mapping template indices {0..T-1} to the actual
	// active parties, and {T..N-1} to the inactive parties (any order).
	phi := make([]int, n)
	idxAct, idxInact := 0, t
	inActive := make(map[int]bool, t)
	for _, p := range sorted {
		inActive[p] = true
	}
	for j := 0; j < n; j++ {
		if inActive[j] {
			phi[idxAct] = j
			idxAct++
		} else {
			phi[idxInact] = j
			idxInact++
		}
	}

	for templateIdx, shares := range tmpl {
		party := phi[templateIdx]
		for _, sh := range shares {
			translated := make(Share, len(sh))
			for i, p := range sh {
				translated[i] = phi[p]
			}
			sort.Ints(translated)
			result[party] = append(result[party], translated)
		}
	}
	return result
}

// fallbackRecover runs a greedy balanced assignment for (T, N) not in the
// hardcoded table. Each secret s_I is assigned to the active-party member of
// I with the lightest current load.
func fallbackRecover(act []int, n, t int) map[int][]Share {
	result := make(map[int][]Share)
	for _, p := range act {
		result[p] = nil
	}
	subsets := RSSSubsets(t, n)
	actSet := make(map[int]bool, len(act))
	for _, p := range act {
		actSet[p] = true
	}
	for _, sh := range subsets {
		best := -1
		bestLoad := 1 << 30
		for _, p := range sh {
			if !actSet[p] {
				continue
			}
			if len(result[p]) < bestLoad {
				best = p
				bestLoad = len(result[p])
			}
		}
		if best < 0 {
			// No active party in this subset — skip; this means an honest
			// subset's secret remains unknown to signers, which is fine for
			// the security argument but means signing this session uses
			// fewer secrets. In practice for valid (T, N) every N-T+1
			// subset has at least one active party since |act| = T.
			continue
		}
		result[best] = append(result[best], sh)
	}
	return result
}

// recoverTemplates encodes Algorithm 6 from Appendix B of the paper. Each
// entry maps a template party index in [0..T-1] to the list of share subsets
// that party is responsible for when act = {0, 1, ..., T-1}.
var recoverTemplates = map[[2]int]map[int][]Share{
	{2, 3}: {
		0: {{0, 1}, {0, 2}},
		1: {{1, 2}},
	},
	{2, 4}: {
		0: {{0, 1, 3}, {0, 2, 3}},
		1: {{0, 1, 2}, {1, 2, 3}},
	},
	{3, 4}: {
		0: {{0, 1}, {0, 3}},
		1: {{1, 2}, {1, 3}},
		2: {{2, 3}, {0, 2}},
	},
	{2, 5}: {
		0: {{0, 1, 3, 4}, {0, 2, 3, 4}, {0, 1, 2, 4}},
		1: {{1, 2, 3, 4}, {0, 1, 2, 3}},
	},
	{3, 5}: {
		0: {{0, 3, 4}, {0, 1, 3}, {0, 1, 4}, {0, 2, 3}},
		1: {{0, 1, 2}, {1, 2, 3}, {1, 2, 4}, {1, 3, 4}},
		2: {{2, 3, 4}, {0, 2, 4}},
	},
	{4, 5}: {
		0: {{0, 1}, {0, 3}, {0, 4}},
		1: {{1, 2}, {1, 3}, {1, 4}},
		2: {{2, 3}, {0, 2}, {2, 4}},
		3: {{3, 4}},
	},
	{2, 6}: {
		0: {{0, 2, 3, 4, 5}, {0, 1, 2, 3, 5}, {0, 1, 2, 4, 5}},
		1: {{1, 2, 3, 4, 5}, {0, 1, 2, 3, 4}, {0, 1, 3, 4, 5}},
	},
	{3, 6}: {
		0: {{0, 1, 3, 4}, {0, 1, 2, 4}, {0, 1, 3, 5}, {0, 3, 4, 5}, {0, 1, 2, 5}},
		1: {{0, 1, 4, 5}, {1, 3, 4, 5}, {1, 2, 3, 5}, {1, 2, 3, 4}, {1, 2, 4, 5}},
		2: {{0, 2, 3, 5}, {0, 2, 4, 5}, {0, 2, 3, 4}, {0, 1, 2, 3}, {2, 3, 4, 5}},
	},
	{4, 6}: {
		0: {{0, 1, 4}, {0, 2, 3}, {0, 1, 5}, {0, 1, 2}, {0, 4, 5}},
		1: {{1, 3, 5}, {1, 3, 4}, {1, 2, 5}, {1, 4, 5}, {1, 2, 4}},
		2: {{2, 4, 5}, {0, 2, 4}, {2, 3, 5}, {2, 3, 4}, {0, 2, 5}},
		3: {{0, 3, 4}, {0, 1, 3}, {1, 2, 3}, {3, 4, 5}, {0, 3, 5}},
	},
	{5, 6}: {
		0: {{0, 1}, {0, 2}, {0, 5}},
		1: {{1, 2}, {1, 3}, {1, 5}},
		2: {{2, 3}, {2, 4}, {2, 5}},
		3: {{0, 3}, {3, 4}, {3, 5}},
		4: {{4, 5}, {0, 4}, {1, 4}},
	},
}
