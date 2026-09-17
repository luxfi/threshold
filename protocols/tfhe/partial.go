// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// The decryption kernel. A share is the LWE secret key Shamir-split
// coefficientwise over Z_q. Member j answers with d_j = c_1·s_j + e_j for
// fresh smudging noise e_j, and c_0 + Σ λ_j d_j = m + e + Σ λ_j e_j rounds to
// the plaintext. Quorums whose λ_j are not integers are refused; see Quorate.
//
// Asharov et al., EUROCRYPT 2012; Mouchet et al., PETS 2021; Bendlin and
// Damgård, TCC 2010.

package tfhe

import (
	"fmt"
	"math/big"

	"github.com/luxfi/fhe"
	"github.com/luxfi/lattice/v7/core/rlwe"
	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
)

// delta returns Δ = total! as a big.Int.
func delta(total int) *big.Int {
	d := big.NewInt(1)
	for k := int64(2); k <= int64(total); k++ {
		d.Mul(d, big.NewInt(k))
	}
	return d
}

// sigma returns the smudging standard deviation for a committee, the largest
// value satisfying max_i |Λ_i|·σ·√t·6 ≤ q/16. It floors at 1, which means the
// parameter set is too narrow for the committee.
func sigma(params rlwe.Parameters, threshold, total int) float64 {
	q := float64(params.Q()[0])
	worst := bound(threshold, total)
	margin := q / 16.0
	bound := 6.0 * root(float64(threshold)) * worst
	if bound <= 0 {
		return 1
	}
	sigma := margin / bound
	if sigma < 1 {
		// Floor at 1 so callers still get *some* masking; whether this
		// is cryptographically sufficient is a parameter-set choice
		// (see comment above).
		sigma = 1
	}
	return sigma
}

// bound returns Δ·C(total-1, threshold-1), the worst-case Lagrange numerator
// over all quorums of that size.
func bound(threshold, total int) float64 {
	if threshold <= 0 || total < threshold {
		return 0
	}
	delta := delta(total)
	binom := new(big.Int).Binomial(int64(total-1), int64(threshold-1))
	w := new(big.Int).Mul(delta, binom)
	f, _ := new(big.Float).SetInt(w).Float64()
	return f
}

// root is Newton's method for sqrt, six iterations.
func root(x float64) float64 {
	if x <= 0 {
		return 0
	}
	z := x / 2
	for i := 0; i < 6; i++ {
		z = (z + x/z) / 2
	}
	return z
}

// Share is one member's Shamir share of the LWE secret key: a polynomial in
// R_q, coefficient domain, whose i-th coefficient is f_i(Index) for the
// degree-(t-1) polynomial sharing the i-th coefficient of s.
type Share struct {
	// Index is the Shamir x-coordinate, 1-based.
	Index int

	// Coeffs is the polynomial s_j ∈ Z_q[X]/(X^N+1) in coefficient form,
	// representing one party's share of s. Length is exactly N.
	Coeffs []uint64

	// Q is the LWE modulus this share is bound to. Recorded so combine
	// can detect cross-parameter mixing.
	Q uint64

	// Total is the committee size used at sharing time. Carried per-share so
	// that a stale share from another key generation is detected at combine
	// time, and so σ can be sized from (threshold, total).
	Total int
}

// Partial is one member's partial decryption of one bit, in NTT domain.
type Partial struct {
	// Index is the Shamir x-coordinate of the contributing share.
	Index int

	// Value is the polynomial d_j = c_1·s_j + e_j in NTT domain.
	// Length is exactly N at level 0.
	Value []uint64

	// Q is the LWE modulus.
	Q uint64

	// Total is the committee size at sharing time, copied from the
	// contributing Share. Combine uses it to derive Δ.
	Total int
}

// split Shamir-splits a whole LWE secret key coefficientwise over Z_q. The
// caller holds the secret while it does so; Keygen is the dealerless path.
func split(skLWE *rlwe.SecretKey, params rlwe.Parameters, threshold, total int) ([]Share, error) {
	if threshold < 1 || threshold > total {
		return nil, fmt.Errorf("tfhe: bad threshold %d for total %d", threshold, total)
	}
	q := params.Q()[0]
	if uint64(total) >= q {
		return nil, fmt.Errorf("tfhe: total %d exceeds LWE modulus %d", total, q)
	}

	// 1) Extract the secret key to standard coefficient form. (Shared helper
	//    coeffs mirrors genSecretKeyFromSampler in reverse: IMForm
	//    then INTT, returning a fresh copy and zeroing its scratch.)
	stdCoeffs := coeffs(params, skLWE)

	// 2) Share s with the same coefficientwise dealing Keygen uses, over a
	//    whole key rather than one member's contribution.
	sub, err := deal(stdCoeffs, q, threshold, total)
	zero(stdCoeffs)
	if err != nil {
		return nil, err
	}

	shares := make([]Share, total)
	for j := 0; j < total; j++ {
		shares[j] = Share{
			Index:  j + 1,
			Coeffs: sub[j],
			Q:      q,
			Total:  total,
		}
	}

	return shares, nil
}

// eval evaluates coeffs[0] + coeffs[1]·x + ... + coeffs[t-1]·x^(t-1)
// modulo q using Horner's method, returning a uint64 in [0, q).
func eval(coeffs []*big.Int, x, q *big.Int) uint64 {
	acc := new(big.Int).Set(coeffs[len(coeffs)-1])
	for k := len(coeffs) - 2; k >= 0; k-- {
		acc.Mul(acc, x)
		acc.Add(acc, coeffs[k])
		acc.Mod(acc, q)
	}
	if acc.Sign() < 0 {
		acc.Add(acc, q)
	}
	return acc.Uint64()
}

// partial returns d_j = c_1·s_j + e_j in NTT at level 0, for smudging noise
// drawn at the given σ. share.Coeffs must not be pre-NTT'd, and prng must
// yield fresh noise on every call.
func (share *Share) partial(
	ct *rlwe.Ciphertext,
	params rlwe.Parameters,
	sigma float64,
	prng sampling.PRNG,
) (*Partial, error) {
	if share == nil {
		return nil, fmt.Errorf("tfhe: nil share")
	}
	q := params.Q()[0]
	if share.Q != q {
		return nil, fmt.Errorf("tfhe: share q=%d does not match params q=%d", share.Q, q)
	}
	ringQ := params.RingQ().AtLevel(0)
	if got := len(share.Coeffs); got != ringQ.N() {
		return nil, fmt.Errorf("tfhe: share length %d != ring N %d", got, ringQ.N())
	}

	// 1) Lift the share into the ring: NTT then MForm, so that
	//    MulCoeffsMontgomery composes.
	sPoly := ringQ.NewPoly()
	copy(sPoly.Coeffs[0], share.Coeffs)
	ringQ.NTT(sPoly, sPoly)
	ringQ.MForm(sPoly, sPoly)

	// 2) c_1 · s_j in NTT/Montgomery. rlwe stores Value[1] in NTT already.
	c1 := ct.Value[1]
	if !ct.IsNTT {
		// NTT into a buffer rather than mutating the caller's ciphertext.
		buf := ringQ.NewPoly()
		ringQ.NTT(c1, buf)
		c1 = buf
	}
	dPoly := ringQ.NewPoly()
	ringQ.MulCoeffsMontgomery(c1, sPoly, dPoly)

	// 3) Smudging noise e_j from a discrete Gaussian truncated at 6σ, sampled
	//    in standard form then NTT'd.
	bound := 6.0 * sigma
	if bound > float64(q)/2 {
		bound = float64(q) / 2
	}
	xeSampler, err := ring.NewSampler(prng, ringQ, ring.DiscreteGaussian{
		Sigma: sigma,
		Bound: bound,
	}, false)
	if err != nil {
		return nil, fmt.Errorf("tfhe: noise sampler: %w", err)
	}
	ePoly := ringQ.NewPoly()
	xeSampler.AtLevel(0).Read(ePoly)
	ringQ.NTT(ePoly, ePoly)
	ringQ.Add(dPoly, ePoly, dPoly)

	// Zero the ring lift; share.Coeffs was untouched.
	sPoly.Zero()
	ePoly.Zero()

	out := &Partial{
		Index: share.Index,
		Value: make([]uint64, ringQ.N()),
		Q:     q,
		Total: share.Total,
	}
	copy(out.Value, dPoly.Coeffs[0])
	return out, nil
}

// combine returns c_0 + Σ λ_j d_j as a plaintext polynomial in NTT. Errors if
// a partial disagrees with params, if indices repeat, if none is supplied, or
// if the quorum is not Quorate. The threshold is the caller's to enforce.
func combine(
	ct *rlwe.Ciphertext,
	partials []*Partial,
	params rlwe.Parameters,
) (*rlwe.Plaintext, error) {
	if len(partials) < 1 {
		return nil, fmt.Errorf("tfhe: no partials supplied")
	}
	q := params.Q()[0]
	total := partials[0].Total
	for _, p := range partials {
		if p == nil {
			return nil, fmt.Errorf("tfhe: nil partial")
		}
		if p.Q != q {
			return nil, fmt.Errorf("tfhe: partial q=%d != params q=%d", p.Q, q)
		}
		if p.Total != total {
			return nil, fmt.Errorf("tfhe: partial total=%d differs from %d", p.Total, total)
		}
	}
	seen := make(map[int]struct{}, len(partials))
	for _, p := range partials {
		if _, dup := seen[p.Index]; dup {
			return nil, fmt.Errorf("tfhe: duplicate partial index %d", p.Index)
		}
		seen[p.Index] = struct{}{}
	}

	// A non-integer coefficient would need a modular inverse, which turns the
	// smudging noise into an arbitrary field element.
	indices := make([]int, len(partials))
	for i, p := range partials {
		indices[i] = p.Index
	}
	lambdas, ok := lagrange(indices)
	if !ok {
		return nil, fmt.Errorf("tfhe: quorum %v has a non-integer Lagrange coefficient; "+
			"pick a quorum satisfying Quorate", indices)
	}

	ringQ := params.RingQ().AtLevel(0)
	qBig := new(big.Int).SetUint64(q)

	// pt = c_0 + Σ_j λ_j d_j in NTT.
	accum := ringQ.NewPoly()
	c0 := ct.Value[0]
	if ct.IsNTT {
		accum.Coeffs[0] = append([]uint64(nil), c0.Coeffs[0]...)
	} else {
		// Defensive NTT into a buffer if the ciphertext is non-NTT.
		ringQ.NTT(c0, accum)
	}

	scratch := ringQ.NewPoly()
	for i, pi := range partials {
		lambdaMod := new(big.Int).Mod(lambdas[i], qBig)
		if lambdaMod.Sign() < 0 {
			lambdaMod.Add(lambdaMod, qBig)
		}
		copy(scratch.Coeffs[0], pi.Value)
		ringQ.MulScalar(scratch, lambdaMod.Uint64(), scratch)
		ringQ.Add(accum, scratch, accum)
	}
	scratch.Zero()

	pt := rlwe.NewPlaintext(params, 0)
	pt.Value.Coeffs[0] = accum.Coeffs[0]
	pt.IsNTT = true
	return pt, nil
}

// Quorate reports whether positions have integer Lagrange coefficients at
// zero, the condition under which combine recovers the plaintext. Positions
// {1,3} give {-3/2, 1/2}; the largest positions always qualify.
func Quorate(indices []int) bool {
	_, ok := lagrange(indices)
	return ok
}

// lagrange returns the coefficients at zero and whether all are integers.
func lagrange(indices []int) ([]*big.Int, bool) {
	out := make([]*big.Int, len(indices))
	for i, xi := range indices {
		num := big.NewInt(1)
		den := big.NewInt(1)
		for j, xj := range indices {
			if j == i {
				continue
			}
			num.Mul(num, big.NewInt(int64(xj)))
			den.Mul(den, big.NewInt(int64(xj-xi)))
		}
		lambda, rem := new(big.Int).QuoRem(num, den, new(big.Int))
		if rem.Sign() != 0 {
			return nil, false
		}
		out[i] = lambda
	}
	return out, true
}

// bit decodes luxfi/fhe's encoding: true at Q/8, false at 7Q/8, so
// coefficient 0 of the INTT decodes true in [0, Q/2).
func bit(pt *rlwe.Plaintext, params rlwe.Parameters) bool {
	ringQ := params.RingQ().AtLevel(0)
	if pt.IsNTT {
		// INTT into a buffer rather than mutating the caller's plaintext.
		out := ringQ.NewPoly()
		ringQ.INTT(pt.Value, out)
		c := out.Coeffs[0][0]
		out.Zero()
		return c < params.Q()[0]>>1
	}
	c := pt.Value.Coeffs[0][0]
	return c < params.Q()[0]>>1
}

// Split Shamir-splits a whole secret key. The caller holds the secret while
// it does so; Keygen is the dealerless path.
func Split(sk *fhe.SecretKey, params fhe.Parameters, threshold, total int) ([]Share, error) {
	return split(sk.SKLWE, params.ParamsLWE(), threshold, total)
}

// Partial returns this share's partial decryption of one bit ciphertext, at
// the σ for (threshold, share.Total). A nil prng draws a fresh one.
func (share *Share) Partial(
	ct *fhe.Ciphertext,
	params fhe.Parameters,
	threshold int,
	prng sampling.PRNG,
) (*Partial, error) {
	if prng == nil {
		var err error
		prng, err = sampling.NewPRNG()
		if err != nil {
			return nil, fmt.Errorf("tfhe: prng: %w", err)
		}
	}
	s := sigma(params.ParamsLWE(), threshold, share.Total)
	return share.partial(ct.Ciphertext, params.ParamsLWE(), s, prng)
}

// Combine recombines partial decryptions of one bit ciphertext and decodes
// the bit.
func Combine(
	ct *fhe.Ciphertext,
	partials []*Partial,
	params fhe.Parameters,
) (bool, error) {
	pt, err := combine(ct.Ciphertext, partials, params.ParamsLWE())
	if err != nil {
		return false, err
	}
	return bit(pt, params.ParamsLWE()), nil
}
