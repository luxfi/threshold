// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsa

// SecurityLevel selects the underlying ML-DSA parameter set (FIPS 204).
type SecurityLevel uint8

const (
	// LevelI corresponds to ML-DSA-44 (NIST category 2).
	LevelI SecurityLevel = 44
	// LevelIII corresponds to ML-DSA-65 (NIST category 3).
	LevelIII SecurityLevel = 65
	// LevelV corresponds to ML-DSA-87 (NIST category 5).
	LevelV SecurityLevel = 87
)

// ThresholdParams holds the per-(T,N) threshold parameters: the randomness ball
// radius r', target ball radius r, expansion factor ν for the first ℓ
// coordinates, and K parallel protocol instances.
//
// Values ported from Figures 9, 10, 11 of the paper (Appendix A). They aim for
// ≥ 1/2 success probability per single protocol execution.
type ThresholdParams struct {
	RPrime uint64 // Randomness ball radius r' (⌊√·⌉ of squared radius)
	R      uint64 // Target ball radius r
	Nu     uint32 // Expansion factor ν for first ℓ coordinates
	K      uint32 // Parallel protocol instances
	// CommPerPartyBytes is the expected per-party communication on the
	// successful path, in bytes.
	CommPerPartyBytes uint64
}

// Params returns (ml-dsa base params, threshold params) for a given security
// level and (T, N). Returns ok=false if the combination is out of the
// supported range (2 ≤ T ≤ N ≤ 6).
func Params(level SecurityLevel, t, n int) (tp ThresholdParams, ok bool) {
	if t < 2 || n < t || n > 6 {
		return ThresholdParams{}, false
	}
	key := tnKey{level, uint8(t), uint8(n)}
	tp, ok = paramTable[key]
	return tp, ok
}

type tnKey struct {
	level SecurityLevel
	t, n  uint8
}

// paramTable is the full (T,N) × level parameter set from the paper.
// ν is identical within a security level: ν=3 (level I), ν=6 (level III), ν=7 (level V).
var paramTable = map[tnKey]ThresholdParams{
	// ML-DSA-44 — Figure 9
	{LevelI, 2, 2}: {252833, 252778, 3, 2, 10500},
	{LevelI, 2, 3}: {310138, 310060, 3, 3, 15800},
	{LevelI, 3, 3}: {246546, 246490, 3, 4, 21000},
	{LevelI, 2, 4}: {305997, 305919, 3, 3, 15800},
	{LevelI, 3, 4}: {279314, 279235, 3, 7, 36800},
	{LevelI, 4, 4}: {243519, 243463, 3, 8, 42000},
	{LevelI, 2, 5}: {285459, 285363, 3, 3, 15800},
	{LevelI, 3, 5}: {282912, 282800, 3, 14, 73500},
	{LevelI, 4, 5}: {259526, 259427, 3, 30, 157400},
	{LevelI, 5, 5}: {239981, 239924, 3, 16, 84000},
	{LevelI, 2, 6}: {300362, 300265, 3, 4, 21000},
	{LevelI, 3, 6}: {277139, 277014, 3, 19, 99800},
	{LevelI, 4, 6}: {268831, 268705, 3, 74, 388400},
	{LevelI, 5, 6}: {250686, 250590, 3, 100, 524800},
	{LevelI, 6, 6}: {219301, 219245, 3, 37, 194200},

	// ML-DSA-65 — Figure 10
	{LevelIII, 2, 2}: {501613, 501495, 6, 3, 22900},
	{LevelIII, 2, 3}: {540378, 540212, 6, 5, 38100},
	{LevelIII, 3, 3}: {510504, 510387, 6, 9, 68500},
	{LevelIII, 2, 4}: {540378, 540212, 6, 6, 45700},
	{LevelIII, 3, 4}: {506928, 506761, 6, 20, 152300},
	{LevelIII, 4, 4}: {433711, 433594, 6, 26, 198000},
	{LevelIII, 2, 5}: {552575, 552371, 6, 8, 61000},
	{LevelIII, 3, 5}: {553145, 552909, 6, 62, 472200},
	{LevelIII, 4, 5}: {474535, 474331, 6, 205, 1561300},
	{LevelIII, 5, 5}: {426032, 425914, 6, 78, 594100},
	{LevelIII, 2, 6}: {571412, 571208, 6, 8, 61000},
	{LevelIII, 3, 6}: {537058, 536793, 6, 95, 723500},
	{LevelIII, 4, 6}: {488969, 488704, 6, 804, 6123300},
	{LevelIII, 5, 6}: {461529, 461324, 6, 1200, 9139200},
	{LevelIII, 6, 6}: {415013, 414896, 6, 250, 1904000},

	// ML-DSA-87 — Figure 11
	{LevelV, 2, 2}: {503192, 503119, 7, 3, 31100},
	{LevelV, 2, 3}: {631703, 631601, 7, 4, 41500},
	{LevelV, 3, 3}: {483180, 483107, 7, 6, 62200},
	{LevelV, 2, 4}: {633006, 632903, 7, 4, 41500},
	{LevelV, 3, 4}: {551854, 551752, 7, 11, 114100},
	{LevelV, 4, 4}: {488031, 487958, 7, 14, 145200},
	{LevelV, 2, 5}: {607820, 607694, 7, 5, 51900},
	{LevelV, 3, 5}: {577546, 577400, 7, 26, 269600},
	{LevelV, 4, 5}: {518510, 518384, 7, 70, 725800},
	{LevelV, 5, 5}: {468287, 468214, 7, 35, 362900},
	{LevelV, 2, 6}: {665232, 665106, 7, 5, 51900},
	{LevelV, 3, 6}: {577704, 577541, 7, 39, 404400},
	{LevelV, 4, 6}: {517853, 517689, 7, 208, 2156600},
	{LevelV, 5, 6}: {479819, 479692, 7, 295, 3058600},
	{LevelV, 6, 6}: {424197, 424124, 7, 87, 902000},
}
