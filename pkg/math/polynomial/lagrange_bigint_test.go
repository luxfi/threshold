// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package polynomial_test

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// p1009 is a small prime used for hand-checkable correctness assertions.
var p1009 = big.NewInt(1009)

// pTfheToy is a 64-bit prime in the ballpark of what a small RLWE coefficient
// modulus looks like; large enough to ensure no test accidentally relies on
// p1009-specific arithmetic, small enough to keep tests fast.
var pTfheToy = func() *big.Int {
	p, _ := new(big.Int).SetString("18446744073709551557", 10) // largest prime < 2^64
	return p
}()

func bigSharesFromValues(ids party.IDSlice, ys []*big.Int) map[party.ID]*big.Int {
	if len(ids) != len(ys) {
		panic("bigSharesFromValues: ids and ys length mismatch")
	}
	m := make(map[party.ID]*big.Int, len(ids))
	for i, id := range ids {
		m[id] = new(big.Int).Set(ys[i])
	}
	return m
}

// Constant polynomial p(x) = c. Every share is c, so p(0) = c regardless of
// which subset is given.
func TestLagrangeAtZeroBigInt_constantPolynomial(t *testing.T) {
	c := big.NewInt(42)
	ids := test.PartyIDs(5)
	ys := make([]*big.Int, len(ids))
	for i := range ys {
		ys[i] = new(big.Int).Set(c)
	}
	shares := bigSharesFromValues(ids, ys)

	got, err := polynomial.LagrangeAtZeroBigInt(shares, p1009)
	require.NoError(t, err)
	assert.Equal(t, 0, got.Cmp(c), "expected p(0) = %v, got %v", c, got)
}

// Round-trip: pick a random polynomial of degree t-1, evaluate it at each
// party's x-coordinate, then recover p(0) via LagrangeAtZeroBigInt and assert
// it matches the polynomial's constant term. This is the property real
// threshold-FHE decryption relies on.
func TestLagrangeAtZeroBigInt_secretRecoveryRoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		n    int
		t    int
		mod  *big.Int
	}{
		{"3-of-3 small prime", 3, 3, p1009},
		{"3-of-5 small prime", 5, 3, p1009},
		{"11-of-21 tfhe-toy prime", 21, 11, pTfheToy},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ids := test.PartyIDs(tc.n)
			ys := make([]*big.Int, tc.n)

			// Random polynomial coefficients a_0..a_{t-1}; a_0 is the secret.
			coeffs := make([]*big.Int, tc.t)
			for i := range coeffs {
				v, err := rand.Int(rand.Reader, tc.mod)
				require.NoError(t, err)
				coeffs[i] = v
			}
			secret := new(big.Int).Set(coeffs[0])

			// Evaluate p at each party's x = bigEndianBytes(id) mod modulus.
			for i, id := range ids {
				x := new(big.Int).SetBytes([]byte(id))
				x.Mod(x, tc.mod)
				y := new(big.Int)
				xPow := big.NewInt(1)
				for _, a := range coeffs {
					term := new(big.Int).Mul(a, xPow)
					y.Add(y, term)
					y.Mod(y, tc.mod)
					xPow.Mul(xPow, x)
					xPow.Mod(xPow, tc.mod)
				}
				ys[i] = y
			}

			// Pick the first t shares (Lagrange combine with a (t, n) sharing
			// needs exactly t evaluation points to recover the degree-(t-1)
			// polynomial).
			subsetIDs := ids[:tc.t]
			subsetYs := ys[:tc.t]
			shares := bigSharesFromValues(subsetIDs, subsetYs)

			got, err := polynomial.LagrangeAtZeroBigInt(shares, tc.mod)
			require.NoError(t, err)
			assert.Equal(t, 0, got.Cmp(secret),
				"expected p(0) = %v, got %v (n=%d, t=%d, mod=%v)",
				secret, got, tc.n, tc.t, tc.mod)
		})
	}
}

// Recovery is subset-invariant: with a (t, n) sharing of a degree-(t-1)
// polynomial, any size-t subset of shares recovers the same secret. We pick
// two different subsets and assert they agree.
func TestLagrangeAtZeroBigInt_subsetIndependence(t *testing.T) {
	const n, threshold = 7, 4
	ids := test.PartyIDs(n)

	// Random degree-(threshold-1) polynomial.
	coeffs := make([]*big.Int, threshold)
	for i := range coeffs {
		v, err := rand.Int(rand.Reader, p1009)
		require.NoError(t, err)
		coeffs[i] = v
	}

	evals := make([]*big.Int, n)
	for i, id := range ids {
		x := new(big.Int).SetBytes([]byte(id))
		x.Mod(x, p1009)
		y := new(big.Int)
		xPow := big.NewInt(1)
		for _, a := range coeffs {
			term := new(big.Int).Mul(a, xPow)
			y.Add(y, term)
			y.Mod(y, p1009)
			xPow.Mul(xPow, x)
			xPow.Mod(xPow, p1009)
		}
		evals[i] = y
	}

	// Subset A: parties 0..threshold-1
	subsetA := bigSharesFromValues(ids[:threshold], evals[:threshold])
	gotA, err := polynomial.LagrangeAtZeroBigInt(subsetA, p1009)
	require.NoError(t, err)

	// Subset B: parties (n-threshold)..n-1
	subsetB := bigSharesFromValues(ids[n-threshold:], evals[n-threshold:])
	gotB, err := polynomial.LagrangeAtZeroBigInt(subsetB, p1009)
	require.NoError(t, err)

	assert.Equal(t, 0, gotA.Cmp(gotB),
		"different subsets must recover the same secret: A=%v, B=%v", gotA, gotB)
}

// Result is always in canonical form: 0 <= result < modulus.
func TestLagrangeAtZeroBigInt_canonicalRange(t *testing.T) {
	ids := test.PartyIDs(3)
	// Use values just below the modulus so any non-reduction would overflow above.
	largeY := new(big.Int).Sub(p1009, big.NewInt(1))
	ys := []*big.Int{largeY, largeY, largeY}
	shares := bigSharesFromValues(ids, ys)

	got, err := polynomial.LagrangeAtZeroBigInt(shares, p1009)
	require.NoError(t, err)
	assert.True(t, got.Sign() >= 0, "result must be non-negative, got %v", got)
	assert.True(t, got.Cmp(p1009) < 0, "result must be < modulus, got %v (modulus %v)", got, p1009)
}

// Error path: empty shares.
func TestLagrangeAtZeroBigInt_emptySharesError(t *testing.T) {
	_, err := polynomial.LagrangeAtZeroBigInt(map[party.ID]*big.Int{}, p1009)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one share required")
}

// Error path: invalid modulus.
func TestLagrangeAtZeroBigInt_invalidModulusError(t *testing.T) {
	ids := test.PartyIDs(2)
	shares := bigSharesFromValues(ids, []*big.Int{big.NewInt(1), big.NewInt(2)})

	cases := []struct {
		name string
		mod  *big.Int
	}{
		{"nil modulus", nil},
		{"modulus zero", big.NewInt(0)},
		{"modulus one", big.NewInt(1)},
		{"modulus negative", big.NewInt(-5)},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := polynomial.LagrangeAtZeroBigInt(shares, tc.mod)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "modulus must be > 1")
		})
	}
}

// Error path: two party IDs reduce to the same x-coordinate mod the modulus.
// We construct this with a small modulus and IDs chosen to collide.
func TestLagrangeAtZeroBigInt_duplicateXError(t *testing.T) {
	// Pick a tiny modulus so single-character IDs collide easily.
	tinyMod := big.NewInt(7)

	// "a" -> 0x61 = 97; "h" -> 0x68 = 104. Both 97 % 7 = 6 and 104 % 7 = 6.
	shares := map[party.ID]*big.Int{
		party.ID("a"): big.NewInt(1),
		party.ID("h"): big.NewInt(2),
	}
	_, err := polynomial.LagrangeAtZeroBigInt(shares, tinyMod)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "same x-coordinate")
}
