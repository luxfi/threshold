// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package primitives re-exports github.com/luxfi/corona/primitives
// through the threshold/protocols/corona alias surface. Downstream
// consumers (luxfi/consensus) target this import path so the consensus
// engine does not depend directly on the corona module.
package primitives

import (
	"math/big"

	"github.com/luxfi/corona/primitives"
	"github.com/luxfi/lattice/v7/ring"
)

// ComputeLagrangeCoefficients returns the Lagrange coefficients for
// the given participant indices T evaluated at zero, in the ring r and
// reduced modulo modulus. The result is keyed by position in T.
// Equivalent to primitives.ComputeLagrangeCoefficients.
func ComputeLagrangeCoefficients(r *ring.Ring, T []int, modulus *big.Int) []ring.Poly {
	return primitives.ComputeLagrangeCoefficients(r, T, modulus)
}
