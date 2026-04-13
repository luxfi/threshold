// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsa

import (
	"crypto/rand"
	"errors"
	"math/big"
)

// ErrReject signals that the hyperball rejection step rejected the candidate.
// Caller retries with fresh randomness or advances to the next parallel K
// instance.
var ErrReject = errors.New("mldsa: rejection")

// HRej implements the imbalanced hyperball rejection of Fig. 4 of the paper.
//
// Inputs:
//   v   - the secret-dependent vector c·s^part split into (v1, v2) with
//         v1 ∈ R^ℓ and v2 ∈ R^k.
//   r   - target ball radius.
//   rP  - randomness ball radius r' (rP ≥ r).
//   nu  - expansion factor ν for the first ℓ coordinates.
//
// Output: z = (z1, z2) rounded back to integers, or ErrReject.
//
// Note: this is the mathematical spec stub. The actual lattice sampling and
// rejection integration with ML-DSA ring Rq live in the per-level adapters
// under mldsa44/, mldsa65/, mldsa87/ (to be added alongside CIRCL binding).
func HRej(v1, v2 []int32, r, rP uint64, nu uint32) (z1, z2 []int32, err error) {
	_ = v1
	_ = v2
	_ = r
	_ = rP
	_ = nu
	return nil, nil, errors.New("mldsa: HRej not yet wired to CIRCL ring — see papers/threshold-mldsa.tex §2.7, Fig.4")
}

// uniformBall draws a uniformly random point in a continuous hyperball of
// radius r' centered at 0, then rounds to integers. This is a scalar helper
// used by the full implementation; kept here as a spec anchor.
func uniformBall(dim int, radius float64) ([]float64, error) {
	out := make([]float64, dim)
	// Sample from Gaussian and normalize; scale by U^{1/d} to uniformize in
	// the ball. Placeholder — real impl uses the ring sampler from luxfi/lattice.
	for i := range out {
		n, err := rand.Int(rand.Reader, big.NewInt(1<<32))
		if err != nil {
			return nil, err
		}
		out[i] = float64(n.Int64()) / float64(1<<32)
	}
	_ = radius
	return out, nil
}
