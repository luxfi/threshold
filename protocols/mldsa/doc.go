// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package mldsa implements the threshold signature scheme of Celi, del Pino,
// Espitau, Niot, Prest — Efficient Threshold ML-DSA (USENIX Security 2026).
//
// Output signatures are byte-compatible with standard FIPS 204 ML-DSA, so
// existing verifiers accept threshold-produced signatures unchanged.
//
// Supported parameter sets:
//   - ML-DSA-44 (NIST level I)
//   - ML-DSA-65 (NIST level III)
//   - ML-DSA-87 (NIST level V)
//
// Threshold configurations: 2 ≤ T ≤ N ≤ 6 (practical range; larger N is
// possible but bandwidth grows super-polynomially).
//
// Security model: static dishonest-majority in the ROM, under the unforgeability
// of standard ML-DSA and the hardness of MLWE for χ_s, χ_r, χ_z.
//
// Rounds per signing attempt: 3. K parallel attempts run concurrently to
// reach ≥ 1/2 success probability per protocol execution.
//
// See ../../papers/threshold-mldsa.tex for the full construction and security
// proof, and doi.org/10.5281/zenodo.17963721 for the reference artifact.
package mldsa
