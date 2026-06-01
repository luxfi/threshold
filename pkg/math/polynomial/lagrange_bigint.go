// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package polynomial

import (
	"errors"
	"math/big"

	"github.com/luxfi/threshold/pkg/party"
)

// LagrangeAtZeroBigInt returns p(0) where p is the polynomial of minimal
// degree passing through the points (x_i, y_i) for every party.ID in shares
// (x_i is derived from the ID exactly the way curve.Scalar does it — bytes
// interpreted big-endian, reduced mod modulus). All arithmetic is performed
// in F_modulus; modulus is expected to be prime (Lagrange combine relies on
// the existence of modular inverses for every non-zero element).
//
// For threshold FHE decryption combining, this is the canonical primitive:
// each party submits its partial-decryption share y_i; the combiner runs
// LagrangeAtZeroBigInt to recover the noisy plaintext value, which the caller
// then rounds against the LWE scaling factor to extract the message bit.
//
// This is the big.Int sibling of Lagrange / LagrangeFor in this package,
// which operate over curve.Scalar for FROST / CMP signing. The big.Int
// variant is intended for ring/lattice arithmetic where the modulus is the
// LWE/RLWE ciphertext modulus rather than an elliptic-curve scalar field.
//
// Error contract:
//
//   - shares MUST contain at least one entry, otherwise the polynomial is
//     undefined and an error is returned.
//   - modulus MUST be > 1.
//   - No two party IDs may reduce to the same x-coordinate (mod modulus);
//     this is enforced before any arithmetic so failures are deterministic.
//   - Any zero denominator (x_j - x_i ≡ 0 mod modulus) is caught explicitly.
//   - A denominator with no modular inverse (only possible if modulus is
//     composite and the denominator shares a factor) is caught explicitly.
//
// The result is always in canonical form: 0 <= result < modulus.
func LagrangeAtZeroBigInt(shares map[party.ID]*big.Int, modulus *big.Int) (*big.Int, error) {
	if len(shares) == 0 {
		return nil, errors.New("polynomial.LagrangeAtZeroBigInt: at least one share required")
	}
	if modulus == nil || modulus.Cmp(big.NewInt(1)) <= 0 {
		return nil, errors.New("polynomial.LagrangeAtZeroBigInt: modulus must be > 1")
	}

	// Resolve x-coordinates up front and detect duplicates. This is cheaper
	// than discovering a duplicate mid-combine when the contributions have
	// already been partially summed.
	xs := make(map[party.ID]*big.Int, len(shares))
	seenX := make(map[string]struct{}, len(shares))
	for id := range shares {
		x := new(big.Int).SetBytes([]byte(id))
		x.Mod(x, modulus)
		key := x.String()
		if _, dup := seenX[key]; dup {
			return nil, errors.New("polynomial.LagrangeAtZeroBigInt: two party IDs reduce to the same x-coordinate mod modulus")
		}
		seenX[key] = struct{}{}
		xs[id] = x
	}

	// p(0) = sum_i y_i * L_i(0)
	// L_i(0) = prod_{j != i} x_j * (x_j - x_i)^{-1}
	result := new(big.Int)
	for id, yi := range shares {
		xi := xs[id]

		numerator := big.NewInt(1)
		denominator := big.NewInt(1)
		for jd, xj := range xs {
			if jd == id {
				continue
			}
			numerator.Mul(numerator, xj)
			numerator.Mod(numerator, modulus)

			diff := new(big.Int).Sub(xj, xi)
			diff.Mod(diff, modulus)
			if diff.Sign() == 0 {
				return nil, errors.New("polynomial.LagrangeAtZeroBigInt: zero denominator (x_j == x_i mod modulus)")
			}
			denominator.Mul(denominator, diff)
			denominator.Mod(denominator, modulus)
		}

		denInv := new(big.Int).ModInverse(denominator, modulus)
		if denInv == nil {
			return nil, errors.New("polynomial.LagrangeAtZeroBigInt: denominator has no inverse mod modulus (modulus likely composite or denominator shares a factor)")
		}

		// Coefficient L_i(0) is numerator * denInv mod modulus.
		coefficient := new(big.Int).Mul(numerator, denInv)
		coefficient.Mod(coefficient, modulus)

		// Accumulate y_i * L_i(0) into the running sum.
		term := new(big.Int).Mul(yi, coefficient)
		result.Add(result, term)
		result.Mod(result, modulus)
	}

	return result, nil
}
