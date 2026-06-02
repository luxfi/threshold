// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package mldsa is the RESEARCH-PREVIEW scaffold for the threshold
// signature scheme of Celi, del Pino, Espitau, Niot, Prest — Efficient
// Threshold ML-DSA (USENIX Security 2026).
//
// STATUS — research preview, NOT production. The current tree ships:
//   - params.go    (T,N) × level parameter sets (Tables 3, 10, 11)
//   - rss.go       replicated secret sharing, hardcoded optimal partitions
//   - hrej.go      imbalanced hyperball rejection — STUB; HRej() returns
//     "not yet wired to CIRCL ring"
//
// The signer itself — keygen.go, sign.go, combine.go, a_posteriori.go —
// does not exist yet. Importing this package and calling anything that
// claims to produce a signature today will fail. Use luxfi/crypto/mldsa
// for production ML-DSA — that is the per-validator FIPS 204 primitive
// shipped through CIRCL, with KAT-pinned determinism. The two are
// complementary: per-validator ML-DSA is the production identity-proof
// lane (e.g. Warp 2.0 MLDSACertSet); threshold ML-DSA is the future
// MPC-aggregated lane, paper-grade today.
//
// Once the signer lands, output signatures will be byte-compatible with
// standard FIPS 204 ML-DSA, so existing verifiers accept threshold-
// produced signatures unchanged. That property is the whole point of
// the construction.
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
